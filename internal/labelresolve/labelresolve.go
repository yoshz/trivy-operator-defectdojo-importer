// SPDX-License-Identifier: GPL-3.0-or-later

// Package labelresolve resolves the labels of the Kubernetes resource that a
// trivy-operator report was generated for, merged with the labels of its
// underlying Pod where one exists.
//
// trivy-operator stamps every report with labels identifying the resource it
// scanned, e.g.:
//
//	trivy-operator.resource.kind: ReplicaSet
//	trivy-operator.resource.name: nginx-6d4cf56db6
//	trivy-operator.resource.namespace: default
//
// For workload reports (VulnerabilityReport, ...) that resource is the
// immediate controller of the Pod (Pod, ReplicaSet, DaemonSet, StatefulSet,
// Job or ReplicationController) - never a higher-level owner like Deployment
// or CronJob - so resolving the Pod is always a single hop away, and its
// labels are merged in as a fallback (the controller's own labels win on
// key conflicts). Other report kinds (e.g. ConfigAuditReport,
// ExposedSecretReport) can reference any kind of resource - Service,
// Ingress, ConfigMap, Role, Namespace, etc. - which never own a Pod but
// still carry labels worth reading. Labels for those are fetched
// generically via the dynamic client and REST mapper; only Pod resolution
// is limited to the pod-owning kinds above.
package labelresolve

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	LabelResourceKind      = "trivy-operator.resource.kind"
	LabelResourceName      = "trivy-operator.resource.name"
	LabelResourceNamespace = "trivy-operator.resource.namespace"
	// LabelResourceNameHash is set by trivy-operator instead of
	// LabelResourceName when the resource's actual name fails Kubernetes
	// label value validation (typically because it's longer than the
	// 63-character label value limit, even though resource names may be up
	// to 253 characters). It holds a hash of the name, not the name itself,
	// so it can't be used to look the resource up directly.
	LabelResourceNameHash = "trivy-operator.resource.name-hash"
)

// Resolver resolves the labels of the resource behind a trivy-operator
// report, merged with the labels of its Pod for pod-owning resource kinds.
type Resolver struct {
	Clientset kubernetes.Interface
	Dynamic   dynamic.Interface
	Discovery discovery.DiscoveryInterface
}

func New(clientset kubernetes.Interface, dynClient dynamic.Interface) *Resolver {
	return &Resolver{
		Clientset: clientset,
		Dynamic:   dynClient,
		Discovery: memory.NewMemCacheClient(clientset.Discovery()),
	}
}

// Resolve returns the labels of the given resource, merged with its Pod's
// labels where one can be found (the resource's own labels win on key
// conflicts). namespace/kind/name are expected to come from the report's
// trivy-operator.resource.* labels. The returned map is nil only when
// nothing could be resolved at all, in which case an error is also
// returned; a partial result (e.g. no Pod found) is returned with a nil
// error, since that's expected for resource kinds that don't own a Pod.
func (r *Resolver) Resolve(ctx context.Context, namespace, kind, name string) (map[string]string, error) {
	if name == "" {
		return nil, fmt.Errorf("empty resource name")
	}

	if strings.EqualFold(kind, "Pod") || kind == "" {
		pod, err := r.Clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return pod.Labels, nil
	}

	controllerLabels, labelsErr := r.controllerLabels(ctx, namespace, kind, name)

	var pod *corev1.Pod
	var podErr error
	switch {
	case strings.EqualFold(kind, "CronJob"):
		pod, podErr = r.resolveCronJobPod(ctx, namespace, name)
	case strings.EqualFold(kind, "Deployment"):
		// trivy-operator does not normally reference Deployments directly,
		// but handle it defensively by walking Deployment -> ReplicaSet -> Pod.
		pod, podErr = r.resolveDeploymentPod(ctx, namespace, name)
	case strings.EqualFold(kind, "ReplicaSet"),
		strings.EqualFold(kind, "DaemonSet"),
		strings.EqualFold(kind, "StatefulSet"),
		strings.EqualFold(kind, "Job"),
		strings.EqualFold(kind, "ReplicationController"):
		pod, podErr = r.podOwnedBy(ctx, namespace, kind, name)
	default:
		// Kind doesn't own a Pod (Service, Ingress, ConfigMap, Namespace,
		// ...) - nothing to resolve there, but controllerLabels above still
		// carries whatever labels the resource itself has.
	}

	var podLabels map[string]string
	if pod != nil {
		podLabels = pod.Labels
	}
	if controllerLabels == nil && podLabels == nil {
		if podErr != nil {
			return nil, podErr
		}
		return nil, labelsErr
	}
	return mergeLabels(controllerLabels, podLabels), nil
}

// mergeLabels combines controllerLabels and podLabels into a single map,
// with controllerLabels taking precedence on key conflicts. Returns nil if
// both are nil.
func mergeLabels(controllerLabels, podLabels map[string]string) map[string]string {
	if controllerLabels == nil && podLabels == nil {
		return nil
	}
	merged := make(map[string]string, len(controllerLabels)+len(podLabels))
	for k, v := range podLabels {
		merged[k] = v
	}
	for k, v := range controllerLabels {
		merged[k] = v
	}
	return merged
}

// controllerLabels fetches the labels of the resource referenced by
// kind/name directly (not any Pod it might control), regardless of what
// kind it is, via the dynamic client.
func (r *Resolver) controllerLabels(ctx context.Context, namespace, kind, name string) (map[string]string, error) {
	gvr, namespaced, err := r.resourceForKind(kind)
	if err != nil {
		return nil, err
	}

	ri := r.Dynamic.Resource(gvr)
	getter := ri.Namespace(namespace)
	if !namespaced {
		getter = ri.Namespace("")
	}

	obj, err := getter.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting %s %s/%s: %w", kind, namespace, name, err)
	}
	return obj.GetLabels(), nil
}

// resourceForKind finds the GroupVersionResource (and whether it's
// namespace-scoped) for the given Kind by searching server discovery data
// across every API group - unlike meta.RESTMapper.RESTMapping, which
// requires the group to already be known and only matches within it. Kind
// alone (as reported by trivy-operator's trivy-operator.resource.kind
// label) isn't enough to pick a group upfront, since e.g. ReplicaSet lives
// in "apps" and Ingress lives in "networking.k8s.io".
func (r *Resolver) resourceForKind(kind string) (schema.GroupVersionResource, bool, error) {
	_, apiResourceLists, err := r.Discovery.ServerGroupsAndResources()
	if len(apiResourceLists) == 0 {
		if err != nil {
			return schema.GroupVersionResource{}, false, fmt.Errorf("discovering API resources: %w", err)
		}
		return schema.GroupVersionResource{}, false, fmt.Errorf("no API resources discovered")
	}
	// A non-nil err alongside non-empty results means some API groups
	// failed to discover (e.g. a broken aggregated API service) - the
	// groups that did succeed are still usable, so don't treat that as fatal.

	for _, list := range apiResourceLists {
		gv, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			continue
		}
		for _, res := range list.APIResources {
			if strings.Contains(res.Name, "/") {
				continue // subresource, e.g. "pods/status"
			}
			if strings.EqualFold(res.Kind, kind) {
				return gv.WithResource(res.Name), res.Namespaced, nil
			}
		}
	}
	return schema.GroupVersionResource{}, false, fmt.Errorf("no known API resource for kind %q", kind)
}

// podOwnedBy returns the first (preferably Running) Pod in namespace owned by
// an object of the given kind/name.
func (r *Resolver) podOwnedBy(ctx context.Context, namespace, kind, name string) (*corev1.Pod, error) {
	pods, err := r.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods in %s: %w", namespace, err)
	}

	var fallback *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, owner := range pod.OwnerReferences {
			if strings.EqualFold(owner.Kind, kind) && owner.Name == name {
				if pod.Status.Phase == corev1.PodRunning {
					return pod, nil
				}
				if fallback == nil {
					fallback = pod
				}
			}
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("no pod in %s owned by %s/%s", namespace, kind, name)
}

func (r *Resolver) resolveCronJobPod(ctx context.Context, namespace, cronJobName string) (*corev1.Pod, error) {
	jobNames, err := r.jobNamesOwnedByCronJob(ctx, namespace, cronJobName)
	if err != nil {
		return nil, err
	}
	for _, jobName := range jobNames {
		if pod, err := r.podOwnedBy(ctx, namespace, "Job", jobName); err == nil {
			return pod, nil
		}
	}
	return nil, fmt.Errorf("no pod found for cronjob %s/%s", namespace, cronJobName)
}

func (r *Resolver) resolveDeploymentPod(ctx context.Context, namespace, deploymentName string) (*corev1.Pod, error) {
	rsNames, err := r.replicaSetNamesOwnedByDeployment(ctx, namespace, deploymentName)
	if err != nil {
		return nil, err
	}
	for _, rsName := range rsNames {
		if pod, err := r.podOwnedBy(ctx, namespace, "ReplicaSet", rsName); err == nil {
			return pod, nil
		}
	}
	return nil, fmt.Errorf("no pod found for deployment %s/%s", namespace, deploymentName)
}

func (r *Resolver) jobNamesOwnedByCronJob(ctx context.Context, namespace, cronJobName string) ([]string, error) {
	jobs, err := r.Clientset.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing jobs in %s: %w", namespace, err)
	}
	var names []string
	for _, job := range jobs.Items {
		for _, owner := range job.OwnerReferences {
			if strings.EqualFold(owner.Kind, "CronJob") && owner.Name == cronJobName {
				names = append(names, job.Name)
			}
		}
	}
	return names, nil
}

func (r *Resolver) replicaSetNamesOwnedByDeployment(ctx context.Context, namespace, deploymentName string) ([]string, error) {
	replicaSets, err := r.Clientset.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing replicasets in %s: %w", namespace, err)
	}
	var names []string
	for _, rs := range replicaSets.Items {
		for _, owner := range rs.OwnerReferences {
			if strings.EqualFold(owner.Kind, "Deployment") && owner.Name == deploymentName {
				names = append(names, rs.Name)
			}
		}
	}
	return names, nil
}
