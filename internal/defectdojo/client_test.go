// SPDX-License-Identifier: GPL-3.0-or-later

package defectdojo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProductExistsExactMatchOnly guards against a real bug: DefectDojo's
// GET /api/v2/products/?name= filter matches by substring (icontains), not
// exact equality. A query for "do-node-agent" can return a non-zero count
// because some other product's name (e.g. "digitalocean-do-node-agent")
// merely contains it - that must not be treated as the exact product
// existing, or the caller wrongly omits product_type_name from
// reimport-scan and DefectDojo 400s with "Product ... does not exist and no
// product_type_name provided".
func TestProductExistsExactMatchOnly(t *testing.T) {
	cases := []struct {
		name    string
		results string
		want    bool
	}{
		{
			name:    "no results",
			results: `{"count": 0, "results": []}`,
			want:    false,
		},
		{
			name:    "exact match present",
			results: `{"count": 1, "results": [{"name": "do-node-agent"}]}`,
			want:    true,
		},
		{
			name:    "only a substring match present",
			results: `{"count": 1, "results": [{"name": "digitalocean-do-node-agent"}]}`,
			want:    false,
		},
		{
			name:    "substring match plus the exact match",
			results: `{"count": 2, "results": [{"name": "digitalocean-do-node-agent"}, {"name": "do-node-agent"}]}`,
			want:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(c.results))
			}))
			defer srv.Close()

			client := New(srv.URL, "token", nil)
			got, err := client.ProductExists(context.Background(), "do-node-agent")
			if err != nil {
				t.Fatalf("ProductExists() error = %v", err)
			}
			if got != c.want {
				t.Errorf("ProductExists() = %v, want %v", got, c.want)
			}
		})
	}
}
