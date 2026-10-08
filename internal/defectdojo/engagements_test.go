// SPDX-License-Identifier: GPL-3.0-or-later

package defectdojo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEngagementsByNameExactMatchOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != "review-1" {
			t.Errorf("name query = %q, want review-1", got)
		}
		w.Write([]byte(`{"next": null, "results": [{"id": 1, "name": "review-1"}, {"id": 2, "name": "review-10"}]}`))
	}))
	defer srv.Close()

	got, err := New(srv.URL, "token", nil).EngagementsByName(context.Background(), "review-1")
	if err != nil {
		t.Fatalf("EngagementsByName() error = %v", err)
	}
	if len(got) != 1 || got[0].ID != 1 {
		t.Errorf("EngagementsByName() = %+v, want only engagement 1", got)
	}
}

func TestEngagementsWithScanTypeFollowsPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/tests/" && r.URL.Query().Get("offset") == "":
			if got := r.URL.Query().Get("scan_type"); got != "Trivy Operator Scan" {
				t.Errorf("scan_type query = %q", got)
			}
			fmt.Fprintf(w, `{"next": "%s/api/v2/tests/?offset=1", "results": [{"id": 10, "engagement": 1, "scan_type": "Trivy Operator Scan"}]}`, srv.URL)
		case r.URL.Path == "/api/v2/tests/":
			w.Write([]byte(`{"next": null, "results": [{"id": 11, "engagement": 3, "scan_type": null, "test_type_name": "Trivy Operator Scan"}]}`))
		case r.URL.Path == "/api/v2/engagements/":
			w.Write([]byte(`{"next": null, "results": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}, {"id": 3, "name": "c"}]}`))
		default:
			t.Errorf("unexpected request %s", r.URL)
		}
	}))
	defer srv.Close()

	got, err := New(srv.URL, "token", nil).EngagementsWithScanType(context.Background(), "Trivy Operator Scan")
	if err != nil {
		t.Fatalf("EngagementsWithScanType() error = %v", err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
		t.Errorf("EngagementsWithScanType() = %+v, want engagements a and c", got)
	}
}

func TestEngagementOnlyHasScanType(t *testing.T) {
	cases := []struct {
		name  string
		tests string
		want  bool
	}{
		{"no tests", `[]`, false},
		{"only importer tests", `[{"id": 1, "scan_type": "Trivy Operator Scan"}, {"id": 2, "scan_type": "Trivy Operator Scan"}]`, true},
		{"mixed tests", `[{"id": 1, "scan_type": "Trivy Operator Scan"}, {"id": 2, "scan_type": "ZAP Scan"}]`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.Query().Get("engagement"); got != "7" {
					t.Errorf("engagement query = %q, want 7", got)
				}
				fmt.Fprintf(w, `{"next": null, "results": %s}`, c.tests)
			}))
			defer srv.Close()

			got, err := New(srv.URL, "token", nil).EngagementOnlyHasScanType(context.Background(), 7, "Trivy Operator Scan")
			if err != nil {
				t.Fatalf("EngagementOnlyHasScanType() error = %v", err)
			}
			if got != c.want {
				t.Errorf("EngagementOnlyHasScanType() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDeleteEngagement(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"deleted", http.StatusNoContent, false},
		{"already gone", http.StatusNotFound, false},
		{"server error", http.StatusInternalServerError, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != "/api/v2/engagements/7/" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				w.WriteHeader(c.status)
			}))
			defer srv.Close()

			err := New(srv.URL, "token", nil).DeleteEngagement(context.Background(), 7)
			if (err != nil) != c.wantErr {
				t.Errorf("DeleteEngagement() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}
