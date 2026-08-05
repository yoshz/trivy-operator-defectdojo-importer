// SPDX-License-Identifier: GPL-3.0-or-later

// Package podresolve finds the Kubernetes Pod that a trivy-operator report
// was generated for, along with the labels of its immediate controller.
//
// trivy-operator stamps every report with labels identifying the resource it
// scanned, e.g.:
//
//	trivy-operator.resource.kind: ReplicaSet
//	trivy-operator.resource.name: nginx-6d4cf56db6
//	trivy-operator.resource.namespace: default
//
// The referenced resource is the immediate controller of the Pod (Pod,
// ReplicaSet, DaemonSet, StatefulSet, Job or ReplicationController) - never
// a higher-level owner like Deployment or CronJob - so resolving the Pod is
// always a single hop away.
package podresolve

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	LabelResourceKind      = "trivy-operator.resource.kind"
	LabelResourceName      = "trivy-operator.resource.name"
	LabelResourceNamespace = "trivy-operator.resource.namespace"
)

// Resolver resolves the Pod behind a trivy-operator report, and the labels
// of the resource that immediately controls it.
type Resolver struct {
	Clientset kubernetes.Interface
}

func New(clientset kubernetes.Interface) *Resolver {
	return &Resolver{Clientset: clientset}
}

// Result holds what could be resolved for a report's underlying resource.
// Either field may be nil if that part couldn't be found (e.g. the
// controller or Pod has since been deleted, or RBAC doesn't permit reading
// it) - callers should treat both as best-effort.
type Result struct {
	// Pod is the Kubernetes Pod the report was generated for.
	Pod *corev1.Pod
	// ControllerLabels are the labels on the resource referenced directly by
	// the report (trivy-operator.resource.kind/name), i.e. the Pod itself
	// when kind is Pod, or its immediate controller (ReplicaSet, DaemonSet,
	// StatefulSet, Job, ReplicationController, ...) otherwise.
	ControllerLabels map[string]string
}

// Resolve looks up the Pod and controller labels for the given resource.
// namespace/kind/name are expected to come from the report's
// trivy-operator.resource.* labels. It returns a partial Result (with nil
// fields for whatever couldn't be found) rather than an error whenever at
// least one piece of information was resolved; an error is returned only
// when nothing could be resolved at all, or the resource kind is unsupported.
func (r *Resolver) Resolve(ctx context.Context, namespace, kind, name string) (Result, error) {
	if name == "" {
		return Result{}, fmt.Errorf("empty resource name")
	}

	if strings.EqualFold(kind, "Pod") || kind == "" {
		pod, err := r.Clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return Result{}, err
		}
		return Result{Pod: pod, ControllerLabels: pod.Labels}, nil
	}

	controllerLabels := r.controllerLabels(ctx, namespace, kind, name)

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
		return Result{}, fmt.Errorf("unsupported resource kind %q for pod resolution", kind)
	}

	if pod == nil && controllerLabels == nil {
		return Result{}, podErr
	}
	return Result{Pod: pod, ControllerLabels: controllerLabels}, nil
}

// controllerLabels fetches the labels of the resource referenced by
// kind/name directly (not the Pod it controls). Returns nil if the object
// couldn't be fetched (deleted, RBAC denied, etc) or kind is unrecognized.
func (r *Resolver) controllerLabels(ctx context.Context, namespace, kind, name string) map[string]string {
	opts := metav1.GetOptions{}
	switch {
	case strings.EqualFold(kind, "ReplicaSet"):
		o, err := r.Clientset.AppsV1().ReplicaSets(namespace).Get(ctx, name, opts)
		if err != nil {
			return nil
		}
		return o.Labels
	case strings.EqualFold(kind, "DaemonSet"):
		o, err := r.Clientset.AppsV1().DaemonSets(namespace).Get(ctx, name, opts)
		if err != nil {
			return nil
		}
		return o.Labels
	case strings.EqualFold(kind, "StatefulSet"):
		o, err := r.Clientset.AppsV1().StatefulSets(namespace).Get(ctx, name, opts)
		if err != nil {
			return nil
		}
		return o.Labels
	case strings.EqualFold(kind, "Deployment"):
		o, err := r.Clientset.AppsV1().Deployments(namespace).Get(ctx, name, opts)
		if err != nil {
			return nil
		}
		return o.Labels
	case strings.EqualFold(kind, "Job"):
		o, err := r.Clientset.BatchV1().Jobs(namespace).Get(ctx, name, opts)
		if err != nil {
			return nil
		}
		return o.Labels
	case strings.EqualFold(kind, "CronJob"):
		o, err := r.Clientset.BatchV1().CronJobs(namespace).Get(ctx, name, opts)
		if err != nil {
			return nil
		}
		return o.Labels
	case strings.EqualFold(kind, "ReplicationController"):
		o, err := r.Clientset.CoreV1().ReplicationControllers(namespace).Get(ctx, name, opts)
		if err != nil {
			return nil
		}
		return o.Labels
	default:
		return nil
	}
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
