// SPDX-License-Identifier: GPL-3.0-or-later

package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// pageSize is the page size requested from DefectDojo's paginated list
// endpoints.
const pageSize = 250

// Engagement is the subset of a DefectDojo engagement used by the importer.
type Engagement struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Product int    `json:"product"`
}

type test struct {
	ID           int    `json:"id"`
	Engagement   int    `json:"engagement"`
	ScanType     string `json:"scan_type"`
	TestTypeName string `json:"test_type_name"`
}

func (t test) isScanType(scanType string) bool {
	// scan_type is empty for tests created before DefectDojo stored it,
	// test_type_name holds the same value for the importer's scan type.
	return t.ScanType == scanType || (t.ScanType == "" && t.TestTypeName == scanType)
}

// EngagementsByName returns the engagements named exactly name, across all
// products.
func (c *Client) EngagementsByName(ctx context.Context, name string) ([]Engagement, error) {
	all, err := listAll[Engagement](ctx, c, "/api/v2/engagements/", url.Values{"name": {name}})
	if err != nil {
		return nil, fmt.Errorf("listing engagements named %q: %w", name, err)
	}
	// Filter client-side as well, see ProductExists for why the API's name
	// filter isn't trusted to be an exact match.
	var out []Engagement
	for _, e := range all {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out, nil
}

// EngagementsWithScanType returns every engagement that contains at least
// one test of the given scan type.
func (c *Client) EngagementsWithScanType(ctx context.Context, scanType string) ([]Engagement, error) {
	tests, err := listAll[test](ctx, c, "/api/v2/tests/", url.Values{"scan_type": {scanType}})
	if err != nil {
		return nil, fmt.Errorf("listing %q tests: %w", scanType, err)
	}
	ids := make(map[int]bool)
	for _, t := range tests {
		if t.isScanType(scanType) {
			ids[t.Engagement] = true
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}

	engagements, err := listAll[Engagement](ctx, c, "/api/v2/engagements/", nil)
	if err != nil {
		return nil, fmt.Errorf("listing engagements: %w", err)
	}
	var out []Engagement
	for _, e := range engagements {
		if ids[e.ID] {
			out = append(out, e)
		}
	}
	return out, nil
}

// EngagementOnlyHasScanType reports whether the engagement contains at least
// one test and all of its tests are of the given scan type, i.e. whether the
// engagement holds nothing but what the importer created.
func (c *Client) EngagementOnlyHasScanType(ctx context.Context, engagementID int, scanType string) (bool, error) {
	tests, err := listAll[test](ctx, c, "/api/v2/tests/", url.Values{"engagement": {strconv.Itoa(engagementID)}})
	if err != nil {
		return false, fmt.Errorf("listing tests of engagement %d: %w", engagementID, err)
	}
	if len(tests) == 0 {
		return false, nil
	}
	for _, t := range tests {
		if !t.isScanType(scanType) {
			return false, nil
		}
	}
	return true, nil
}

// DeleteEngagement deletes an engagement, including its tests and findings.
func (c *Client) DeleteEngagement(ctx context.Context, engagementID int) error {
	u := fmt.Sprintf("%s/api/v2/engagements/%d/", c.BaseURL, engagementID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("deleting engagement %d: %w", engagementID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // already gone
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deleting engagement %d returned status %d: %s", engagementID, resp.StatusCode, string(body))
	}
	return nil
}

// listAll fetches every page of a DefectDojo list endpoint, following the
// "next" links in the paginated responses.
func listAll[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	q.Set("limit", strconv.Itoa(pageSize))
	next := c.BaseURL + path + "?" + q.Encode()

	var out []T
	for next != "" {
		var page struct {
			Next    *string `json:"next"`
			Results []T     `json:"results"`
		}
		if err := c.getJSON(ctx, next, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Results...)
		next = ""
		if page.Next != nil {
			next = *page.Next
		}
	}
	return out, nil
}

func (c *Client) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d for GET %s: %s", resp.StatusCode, u, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
