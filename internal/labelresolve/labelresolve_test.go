// SPDX-License-Identifier: GPL-3.0-or-later

package labelresolve

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	clienttesting "k8s.io/client-go/testing"
)

// fakeDiscovery builds a discovery.DiscoveryInterface backed by the given
// API resource lists, mirroring what a real cluster's discovery API returns.
func fakeDiscovery(lists ...*metav1.APIResourceList) discovery.DiscoveryInterface {
	return &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{Resources: lists}}
}

// TestResolveNonPodOwningKind ensures that report kinds that never own a Pod
// (e.g. Service, backing a ConfigAuditReport) still resolve their own
// labels, rather than being rejected as "unsupported".
func TestResolveNonPodOwningKind(t *testing.T) {
	svc := &corev1.Service{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", Labels: map[string]string{"app.kubernetes.io/name": "web"}},
	}

	clientset := fake.NewSimpleClientset()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme.Scheme, svc)
	disc := fakeDiscovery(&metav1.APIResourceList{
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{{Name: "services", Kind: "Service", Namespaced: true}},
	})

	r := &Resolver{Clientset: clientset, Dynamic: dynClient, Discovery: disc}

	labels, err := r.Resolve(context.Background(), "default", "Service", "web")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := labels["app.kubernetes.io/name"]; got != "web" {
		t.Errorf(`Resolve()["app.kubernetes.io/name"] = %q, want %q`, got, "web")
	}
}

// TestResolveClusterScopedKind ensures cluster-scoped resources (e.g. Node,
// which a NodeInfo-related report could reference) resolve without a
// namespace lookup failure.
func TestResolveClusterScopedKind(t *testing.T) {
	node := &corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{Name: "node-1", Labels: map[string]string{"kubernetes.io/hostname": "node-1"}},
	}

	clientset := fake.NewSimpleClientset()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme.Scheme, node)
	disc := fakeDiscovery(&metav1.APIResourceList{
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{{Name: "nodes", Kind: "Node", Namespaced: false}},
	})

	r := &Resolver{Clientset: clientset, Dynamic: dynClient, Discovery: disc}

	labels, err := r.Resolve(context.Background(), "", "Node", "node-1")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := labels["kubernetes.io/hostname"]; got != "node-1" {
		t.Errorf(`Resolve()["kubernetes.io/hostname"] = %q, want %q`, got, "node-1")
	}
}

// TestResolveNonCoreGroupKind ensures kinds that live outside the core ""
// API group (ReplicaSet is in "apps") are still discoverable - a plain
// schema.GroupKind{Kind: kind} lookup against a RESTMapper silently only
// matches the core group, which previously made this resolve to nothing.
func TestResolveNonCoreGroupKind(t *testing.T) {
	rs := &appsv1.ReplicaSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"},
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-6d4cf56db6", Namespace: "default", Labels: map[string]string{"app.kubernetes.io/name": "nginx"}},
	}

	clientset := fake.NewSimpleClientset()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme.Scheme, rs)
	disc := fakeDiscovery(&metav1.APIResourceList{
		GroupVersion: "apps/v1",
		APIResources: []metav1.APIResource{{Name: "replicasets", Kind: "ReplicaSet", Namespaced: true}},
	})

	r := &Resolver{Clientset: clientset, Dynamic: dynClient, Discovery: disc}

	labels, err := r.Resolve(context.Background(), "default", "ReplicaSet", "nginx-6d4cf56db6")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := labels["app.kubernetes.io/name"]; got != "nginx" {
		t.Errorf(`Resolve()["app.kubernetes.io/name"] = %q, want %q`, got, "nginx")
	}
}

// TestResolveMergesControllerAndPodLabels ensures that for pod-owning kinds,
// the controller's own labels and its Pod's labels are merged - with the
// controller's values winning on key conflicts, since it's the more
// deliberately-set metadata (Pods often carry extra generated labels like
// pod-template-hash).
func TestResolveMergesControllerAndPodLabels(t *testing.T) {
	rs := &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "nginx-6d4cf56db6", Namespace: "default",
			Labels: map[string]string{"app.kubernetes.io/name": "controller-app", "team": "platform"},
		},
	}
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "nginx-6d4cf56db6-abcde", Namespace: "default",
			Labels: map[string]string{"app.kubernetes.io/name": "pod-app", "pod-template-hash": "6d4cf56db6"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "nginx-6d4cf56db6"},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	clientset := fake.NewSimpleClientset(pod)
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme.Scheme, rs)
	disc := fakeDiscovery(&metav1.APIResourceList{
		GroupVersion: "apps/v1",
		APIResources: []metav1.APIResource{{Name: "replicasets", Kind: "ReplicaSet", Namespaced: true}},
	})

	r := &Resolver{Clientset: clientset, Dynamic: dynClient, Discovery: disc}

	labels, err := r.Resolve(context.Background(), "default", "ReplicaSet", "nginx-6d4cf56db6")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := labels["app.kubernetes.io/name"]; got != "controller-app" {
		t.Errorf(`Resolve()["app.kubernetes.io/name"] = %q, want %q (controller label should win)`, got, "controller-app")
	}
	if got := labels["team"]; got != "platform" {
		t.Errorf(`Resolve()["team"] = %q, want %q (controller-only label)`, got, "platform")
	}
	if got := labels["pod-template-hash"]; got != "6d4cf56db6" {
		t.Errorf(`Resolve()["pod-template-hash"] = %q, want %q (pod-only label)`, got, "6d4cf56db6")
	}
}
