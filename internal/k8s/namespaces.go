// SPDX-License-Identifier: GPL-3.0-or-later

package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/defectdojo"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/metrics"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/naming"
)

// reconcileInterval is how often DefectDojo is checked for engagements of
// namespaces that were deleted while no delete event was observed (e.g.
// while the importer wasn't running).
const reconcileInterval = time.Hour

// scanType is the DefectDojo scan type of every test the importer creates.
const scanType = "Trivy Operator Scan"

// namespaceCleaner deletes the DefectDojo engagements of deleted namespaces.
type namespaceCleaner struct {
	c        *Controller
	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer
	queue    workqueue.TypedRateLimitingInterface[string]
}

func (c *Controller) newNamespaceCleaner() *namespaceCleaner {
	factory := informers.NewSharedInformerFactory(c.clientset, resyncPeriod)
	informer := factory.Core().V1().Namespaces().Informer()
	queue := workqueue.NewTypedRateLimitingQueue[string](workqueue.DefaultTypedControllerRateLimiter[string]())

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tombstone.Obj
			}
			if ns, ok := obj.(*corev1.Namespace); ok && c.namespaceAllowed(ns.Name) {
				queue.Add(ns.Name)
			}
		},
	})

	return &namespaceCleaner{c: c, factory: factory, informer: informer, queue: queue}
}

func (n *namespaceCleaner) run(ctx context.Context) error {
	n.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), n.informer.HasSynced) {
		return fmt.Errorf("failed to sync informer cache for namespaces")
	}
	slog.Info("deleting DefectDojo engagements of removed namespaces")

	go func() {
		<-ctx.Done()
		n.queue.ShutDown()
	}()
	go n.reconcileLoop(ctx)

	for n.processNextItem(ctx) {
	}
	return nil
}

func (n *namespaceCleaner) processNextItem(ctx context.Context) bool {
	namespace, shutdown := n.queue.Get()
	if shutdown {
		return false
	}
	defer n.queue.Done(namespace)

	if err := n.deleteNamespace(ctx, namespace); err != nil {
		slog.Error("deleting engagements of removed namespace failed, will retry", "namespace", namespace, "error", err)
		n.queue.AddRateLimited(namespace)
		return true
	}
	n.queue.Forget(namespace)
	return true
}

// deleteNamespace deletes the engagements of a namespace that was just
// deleted from the cluster.
func (n *namespaceCleaner) deleteNamespace(ctx context.Context, namespace string) error {
	name, err := n.engagementName(namespace)
	if err != nil {
		return err
	}
	engagements, err := n.c.dd.EngagementsByName(ctx, name)
	if err != nil {
		return err
	}
	for _, e := range engagements {
		if err := n.deleteEngagement(ctx, e, namespace); err != nil {
			return err
		}
	}
	return nil
}

func (n *namespaceCleaner) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		if err := n.reconcile(ctx); err != nil {
			slog.Error("reconciling engagements of removed namespaces failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// reconcile deletes the engagements of namespaces that no longer exist: every
// engagement with importer tests whose name doesn't belong to an existing
// namespace.
func (n *namespaceCleaner) reconcile(ctx context.Context) error {
	namespaces, err := n.liveNamespaces()
	if err != nil {
		return err
	}
	live := make(map[string]bool, len(namespaces))
	for _, ns := range namespaces {
		name, err := n.engagementName(ns)
		if err != nil {
			return err
		}
		live[name] = true
	}

	engagements, err := n.c.dd.EngagementsWithScanType(ctx, scanType)
	if err != nil {
		return err
	}
	for _, e := range engagements {
		if live[e.Name] {
			continue
		}
		if err := n.deleteEngagement(ctx, e, ""); err != nil {
			return err
		}
	}
	return nil
}

func (n *namespaceCleaner) liveNamespaces() ([]string, error) {
	lister := cache.NewGenericLister(n.informer.GetIndexer(), corev1.Resource("namespaces"))
	objs, err := lister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	out := make([]string, 0, len(objs))
	for _, obj := range objs {
		if ns, ok := obj.(*corev1.Namespace); ok {
			out = append(out, ns.Name)
		}
	}
	return out, nil
}

func (n *namespaceCleaner) engagementName(namespace string) (string, error) {
	name, err := naming.Render(n.c.cfg.EngagementNameTemplate, naming.Context{Namespace: namespace})
	if err != nil {
		return "", fmt.Errorf("rendering engagement name for namespace %s: %w", namespace, err)
	}
	return name, nil
}

// deleteEngagement deletes an engagement, but only when it holds nothing but
// importer tests, so engagements shared with other scans are left alone.
func (n *namespaceCleaner) deleteEngagement(ctx context.Context, e defectdojo.Engagement, namespace string) error {
	owned, err := n.c.dd.EngagementOnlyHasScanType(ctx, e.ID, scanType)
	if err != nil {
		return err
	}
	if !owned {
		slog.Warn("not deleting engagement of removed namespace, it contains other tests than "+scanType,
			"engagement", e.Name, "engagementID", e.ID, "namespace", namespace)
		return nil
	}

	if n.c.cfg.DryRun {
		slog.Info("dry-run: would delete engagement of removed namespace",
			"engagement", e.Name, "engagementID", e.ID, "product", e.Product, "namespace", namespace)
		return nil
	}
	if err := n.c.dd.DeleteEngagement(ctx, e.ID); err != nil {
		metrics.EngagementsDeletedTotal.WithLabelValues("failed").Inc()
		return err
	}
	metrics.EngagementsDeletedTotal.WithLabelValues("success").Inc()
	slog.Info("deleted engagement of removed namespace",
		"engagement", e.Name, "engagementID", e.ID, "product", e.Product, "namespace", namespace)
	return nil
}
