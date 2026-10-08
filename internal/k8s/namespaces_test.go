// SPDX-License-Identifier: GPL-3.0-or-later

package k8s

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/config"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/defectdojo"
)

// fakeDefectDojo serves the engagement and test endpoints used by the
// namespace cleaner and records deleted engagements.
type fakeDefectDojo struct {
	engagements map[int]string   // id -> name
	tests       map[int][]string // engagement id -> scan types

	mu      sync.Mutex
	deleted []int
}

func (f *fakeDefectDojo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/engagements/"):
		var id int
		fmt.Sscanf(r.URL.Path, "/api/v2/engagements/%d/", &id)
		f.mu.Lock()
		f.deleted = append(f.deleted, id)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/api/v2/engagements/":
		var results []string
		for id, name := range f.engagements {
			if n := q.Get("name"); n == "" || n == name {
				results = append(results, fmt.Sprintf(`{"id": %d, "name": %q}`, id, name))
			}
		}
		fmt.Fprintf(w, `{"next": null, "results": [%s]}`, strings.Join(results, ","))
	case r.URL.Path == "/api/v2/tests/":
		var results []string
		for engagement, scanTypes := range f.tests {
			if e := q.Get("engagement"); e != "" && e != fmt.Sprint(engagement) {
				continue
			}
			for _, st := range scanTypes {
				if s := q.Get("scan_type"); s != "" && s != st {
					continue
				}
				results = append(results, fmt.Sprintf(`{"engagement": %d, "scan_type": %q}`, engagement, st))
			}
		}
		fmt.Fprintf(w, `{"next": null, "results": [%s]}`, strings.Join(results, ","))
	default:
		http.Error(w, "unexpected request "+r.URL.String(), http.StatusBadRequest)
	}
}

func (f *fakeDefectDojo) deletedIDs() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]int(nil), f.deleted...)
	sort.Ints(out)
	return out
}

func newTestCleaner(t *testing.T, dd *fakeDefectDojo, cfg *config.Config, namespaces ...string) *namespaceCleaner {
	t.Helper()
	srv := httptest.NewServer(dd)
	t.Cleanup(srv.Close)

	var objs []runtime.Object
	for _, ns := range namespaces {
		objs = append(objs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	}
	ctrl := NewController(cfg, nil, fake.NewSimpleClientset(objs...), defectdojo.New(srv.URL, "token", nil))
	cleaner := ctrl.newNamespaceCleaner()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cleaner.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), cleaner.informer.HasSynced) {
		t.Fatal("namespace informer did not sync")
	}
	return cleaner
}

func TestReconcileDeletesEngagementsOfRemovedNamespaces(t *testing.T) {
	dd := &fakeDefectDojo{
		engagements: map[int]string{
			1: "production",   // namespace exists
			2: "review-old",   // namespace removed, importer tests only
			3: "review-mixed", // namespace removed, but also holds another scan
			4: "review-old",   // same namespace, another product
			5: "manual",       // no importer tests at all
		},
		tests: map[int][]string{
			1: {scanType},
			2: {scanType, scanType},
			3: {scanType, "ZAP Scan"},
			4: {scanType},
			5: {"ZAP Scan"},
		},
	}
	cleaner := newTestCleaner(t, dd, &config.Config{EngagementNameTemplate: "{{.Namespace}}"}, "production", "kube-system")

	if err := cleaner.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile() error = %v", err)
	}
	if got, want := dd.deletedIDs(), []int{2, 4}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("deleted engagements = %v, want %v", got, want)
	}
}

func TestDeleteNamespaceOnlyDeletesItsEngagements(t *testing.T) {
	dd := &fakeDefectDojo{
		engagements: map[int]string{1: "review-1", 2: "review-10", 3: "review-1"},
		tests:       map[int][]string{1: {scanType}, 2: {scanType}, 3: {scanType}},
	}
	cleaner := newTestCleaner(t, dd, &config.Config{EngagementNameTemplate: "{{.Namespace}}"})

	if err := cleaner.deleteNamespace(context.Background(), "review-1"); err != nil {
		t.Fatalf("deleteNamespace() error = %v", err)
	}
	if got, want := dd.deletedIDs(), []int{1, 3}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("deleted engagements = %v, want %v", got, want)
	}
}

func TestDryRunDeletesNothing(t *testing.T) {
	dd := &fakeDefectDojo{
		engagements: map[int]string{1: "review-old"},
		tests:       map[int][]string{1: {scanType}},
	}
	cleaner := newTestCleaner(t, dd, &config.Config{EngagementNameTemplate: "{{.Namespace}}", DryRun: true})

	if err := cleaner.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile() error = %v", err)
	}
	if got := dd.deletedIDs(); len(got) != 0 {
		t.Errorf("deleted engagements = %v in dry-run, want none", got)
	}
}
