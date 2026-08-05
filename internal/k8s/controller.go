// SPDX-License-Identifier: GPL-3.0-or-later

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/config"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/defectdojo"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/mapping"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/metrics"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/naming"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/nsmatch"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/podresolve"
)

const resyncPeriod = 10 * time.Hour

// Controller watches the configured trivy-operator report CRDs and forwards
// newly observed reports to DefectDojo.
type Controller struct {
	cfg       *config.Config
	dynClient dynamic.Interface
	resolver  *podresolve.Resolver
	dd        *defectdojo.Client
}

func NewController(cfg *config.Config, dynClient dynamic.Interface, clientset kubernetes.Interface, dd *defectdojo.Client) *Controller {
	return &Controller{
		cfg:       cfg,
		dynClient: dynClient,
		resolver:  podresolve.New(clientset),
		dd:        dd,
	}
}

// namespaceAllowed reports whether reports from namespace should be
// processed, per cfg.IncludeNamespaces/ExcludeNamespaces. An empty
// IncludeNamespaces means every namespace is a candidate; ExcludeNamespaces
// always wins when a namespace matches both.
func (c *Controller) namespaceAllowed(namespace string) bool {
	if len(c.cfg.ExcludeNamespaces) > 0 && nsmatch.MatchAny(c.cfg.ExcludeNamespaces, namespace) {
		return false
	}
	if len(c.cfg.IncludeNamespaces) > 0 && !nsmatch.MatchAny(c.cfg.IncludeNamespaces, namespace) {
		return false
	}
	return true
}

// Run starts one watcher per configured report type and blocks until ctx is
// cancelled.
func (c *Controller) Run(ctx context.Context) error {
	var watchers []*reportWatcher
	for _, report := range c.cfg.Reports {
		w := c.newReportWatcher(report)
		watchers = append(watchers, w)
		go w.factory.Start(ctx.Done())
	}

	for _, w := range watchers {
		if !cache.WaitForCacheSync(ctx.Done(), w.informer.HasSynced) {
			return fmt.Errorf("failed to sync informer cache for %s", w.gvr.Resource)
		}
		slog.Info("watching report resource", "resource", w.gvr.Resource, "group", w.gvr.Group, "version", w.gvr.Version)
		go w.run(ctx, c)
	}

	<-ctx.Done()
	return nil
}

type reportWatcher struct {
	gvr      schema.GroupVersionResource
	factory  dynamicinformer.DynamicSharedInformerFactory
	informer cache.SharedIndexInformer
	queue    workqueue.RateLimitingInterface
}

func (c *Controller) newReportWatcher(resource string) *reportWatcher {
	gvr := schema.GroupVersionResource{
		Group:    c.cfg.ReportGroup,
		Version:  c.cfg.ReportVersion,
		Resource: resource,
	}

	var tweak dynamicinformer.TweakListOptionsFunc
	if c.cfg.Label != "" {
		selector := c.cfg.Label
		if c.cfg.LabelValue != "" {
			selector = fmt.Sprintf("%s=%s", c.cfg.Label, c.cfg.LabelValue)
		}
		tweak = func(opts *metav1.ListOptions) {
			opts.LabelSelector = selector
		}
	}

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		c.dynClient, resyncPeriod, metav1.NamespaceAll, tweak,
	)

	informer := factory.ForResource(gvr).Informer()
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if u, ok := obj.(*unstructured.Unstructured); ok && !c.namespaceAllowed(u.GetNamespace()) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
	})

	return &reportWatcher{gvr: gvr, factory: factory, informer: informer, queue: queue}
}

func (w *reportWatcher) run(ctx context.Context, c *Controller) {
	defer w.queue.ShutDown()
	go func() {
		<-ctx.Done()
	}()
	for w.processNextItem(ctx, c) {
	}
}

func (w *reportWatcher) processNextItem(ctx context.Context, c *Controller) bool {
	key, shutdown := w.queue.Get()
	if shutdown {
		return false
	}
	defer w.queue.Done(key)

	obj, exists, err := w.informer.GetIndexer().GetByKey(key.(string))
	if err != nil {
		slog.Error("fetching object from cache", "key", key, "error", err)
		w.queue.AddRateLimited(key)
		return true
	}
	if !exists {
		w.queue.Forget(key)
		return true
	}

	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		slog.Error("unexpected object type in informer cache", "key", key)
		w.queue.Forget(key)
		return true
	}

	if err := c.handleReport(ctx, u.DeepCopy()); err != nil {
		slog.Error("processing report failed, will retry", "key", key, "error", err)
		w.queue.AddRateLimited(key)
		return true
	}

	w.queue.Forget(key)
	return true
}

func (c *Controller) handleReport(ctx context.Context, obj *unstructured.Unstructured) error {
	start := time.Now()
	defer func() { metrics.ProcessingSeconds.Observe(time.Since(start).Seconds()) }()

	namespace := obj.GetNamespace()
	name := obj.GetName()
	kind := obj.GetKind()

	slog.Info("processing report", "kind", kind, "name", name, "namespace", namespace)

	labels := obj.GetLabels()
	resourceKind := labels[podresolve.LabelResourceKind]
	resourceName := labels[podresolve.LabelResourceName]
	resourceNamespace := labels[podresolve.LabelResourceNamespace]
	if resourceNamespace == "" {
		resourceNamespace = namespace
	}
	if resourceName == "" {
		resourceKind = "Pod"
		resourceName = name
	}

	var podName string
	var podLabels map[string]string
	result, err := c.resolver.Resolve(ctx, resourceNamespace, resourceKind, resourceName)
	if err != nil {
		slog.Warn("could not resolve related pod or controller, falling back to default product name",
			"namespace", resourceNamespace, "resourceKind", resourceKind, "resourceName", resourceName, "error", err)
	} else {
		if result.Pod != nil {
			podName = result.Pod.Name
			podLabels = result.Pod.Labels
		}
	}

	productType := mapping.ProductType(c.cfg, namespace)
	productName := mapping.ProductName(c.cfg, result.ControllerLabels, podLabels)

	nctx := naming.Context{
		Namespace:    namespace,
		ReportName:   name,
		ReportKind:   kind,
		ResourceKind: resourceKind,
		ResourceName: resourceName,
		PodName:      podName,
		PodLabels:    podLabels,
	}

	engagementName, err := naming.Render(c.cfg.EngagementNameTemplate, nctx)
	if err != nil {
		return fmt.Errorf("rendering engagement name: %w", err)
	}
	service, err := naming.Render(c.cfg.ServiceNameTemplate, nctx)
	if err != nil {
		return fmt.Errorf("rendering service name: %w", err)
	}
	environment, ok := mapping.Environment(c.cfg, namespace)
	if !ok {
		environment, err = naming.Render(c.cfg.EnvNameTemplate, nctx)
		if err != nil {
			return fmt.Errorf("rendering environment name: %w", err)
		}
	}
	testTitle, err := naming.Render(c.cfg.TestTitleTemplate, nctx)
	if err != nil {
		return fmt.Errorf("rendering test title: %w", err)
	}
	tagsRendered, err := naming.Render(c.cfg.TagsTemplate, nctx)
	if err != nil {
		return fmt.Errorf("rendering tags: %w", err)
	}
	var tags []string
	for _, t := range strings.Split(tagsRendered, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}

	if c.cfg.DryRun {
		slog.Info("dry-run: resolved report mapping (nothing sent to DefectDojo)",
			"kind", kind, "report", name, "namespace", namespace,
			"resourceKind", resourceKind, "resourceName", resourceName,
			"podName", podName, "controllerLabels", result.ControllerLabels, "podLabels", podLabels,
			"productType", productType, "productName", productName,
			"engagement", engagementName, "service", service, "environment", environment,
			"testTitle", testTitle, "tags", tags)
		metrics.RequestsTotal.WithLabelValues("dry-run").Inc()
		return nil
	}

	fileBody, err := json.Marshal(obj.Object)
	if err != nil {
		return fmt.Errorf("marshaling report to json: %w", err)
	}

	productExists, err := c.dd.ProductExists(ctx, productName)
	if err != nil {
		slog.Warn("could not check if product exists, assuming it doesn't", "product", productName, "error", err)
		productExists = false
	}

	req := defectdojo.ReimportScanRequest{
		Active:                       c.cfg.Active,
		Verified:                     c.cfg.Verified,
		CloseOldFindings:             c.cfg.CloseOldFindings,
		CloseOldFindingsProductScope: c.cfg.CloseOldFindingsProductScope,
		PushToJira:                   c.cfg.PushToJira,
		MinimumSeverity:              c.cfg.MinimumSeverity,
		AutoCreateContext:            c.cfg.AutoCreateContext,
		DeduplicationOnEngagement:    c.cfg.DeduplicationOnEngagement,
		DoNotReactivate:              c.cfg.DoNotReactivate,
		ScanType:                     "Trivy Operator Scan",
		EngagementName:               engagementName,
		ProductName:                  productName,
		Service:                      service,
		Environment:                  environment,
		TestTitle:                    testTitle,
		Tags:                         tags,
		FileName:                     "report.json",
		FileBody:                     fileBody,
	}
	if !productExists {
		req.ProductTypeName = productType
	}

	if err := c.dd.ReimportScan(ctx, req); err != nil {
		metrics.RequestsTotal.WithLabelValues("failed").Inc()
		return fmt.Errorf("reimport-scan for %s/%s: %w", namespace, name, err)
	}

	metrics.RequestsTotal.WithLabelValues("success").Inc()
	slog.Info("imported report into defectdojo", "kind", kind, "name", name, "namespace", namespace,
		"product", productName, "productType", productType, "engagement", engagementName)
	return nil
}
