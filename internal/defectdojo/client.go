// SPDX-License-Identifier: GPL-3.0-or-later

// Package defectdojo is a minimal client for the DefectDojo v2 API endpoints
// used by the importer: checking whether a product exists, and reimporting
// a scan.
package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
)

type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

func New(baseURL, apiKey string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{BaseURL: baseURL, APIKey: apiKey, HTTPClient: httpClient}
}

func (c *Client) authHeader() string {
	return "Token " + c.APIKey
}

// ProductExists reports whether a product with exactly the given name
// already exists in DefectDojo. Mirrors the original operator's behavior of
// treating lookup errors as "does not exist" so the caller can still
// attempt product creation.
//
// DefectDojo's GET /api/v2/products/?name= filter matches by substring
// (icontains), not exact equality, so a non-zero "count" in the response
// does not by itself mean a product with this exact name exists - it only
// means some product's name contains it as a substring. We therefore check
// the returned results for an exact name match rather than trusting count.
func (c *Client) ProductExists(ctx context.Context, name string) (bool, error) {
	u := c.BaseURL + "/api/v2/products/?" + url.Values{"name": {name}}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unexpected status %d checking product %q: %s", resp.StatusCode, name, string(body))
	}

	var payload struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, err
	}
	for _, p := range payload.Results {
		if p.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// ReimportScanRequest holds the form fields sent to /api/v2/reimport-scan/.
type ReimportScanRequest struct {
	Active                       bool
	Verified                     bool
	CloseOldFindings             bool
	CloseOldFindingsProductScope bool
	PushToJira                   bool
	MinimumSeverity              string
	AutoCreateContext            bool
	DeduplicationOnEngagement    bool
	DoNotReactivate              bool
	ScanType                     string
	EngagementName               string
	ProductName                  string
	ProductTypeName              string // omitted from the request when empty
	Service                      string
	Environment                  string
	TestTitle                    string
	Tags                         []string

	FileName string
	FileBody []byte
}

// ReimportScan uploads a report to DefectDojo's reimport-scan endpoint,
// which creates the product/engagement/test as needed and is safe to call
// repeatedly for the same report (it upserts findings rather than
// duplicating them).
func (c *Client) ReimportScan(ctx context.Context, r ReimportScanRequest) error {
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)

	fields := map[string]string{
		"active":                           strconv.FormatBool(r.Active),
		"verified":                         strconv.FormatBool(r.Verified),
		"close_old_findings":               strconv.FormatBool(r.CloseOldFindings),
		"close_old_findings_product_scope": strconv.FormatBool(r.CloseOldFindingsProductScope),
		"push_to_jira":                     strconv.FormatBool(r.PushToJira),
		"minimum_severity":                 r.MinimumSeverity,
		"auto_create_context":              strconv.FormatBool(r.AutoCreateContext),
		"deduplication_on_engagement":      strconv.FormatBool(r.DeduplicationOnEngagement),
		"scan_type":                        r.ScanType,
		"engagement_name":                  r.EngagementName,
		"product_name":                     r.ProductName,
		"service":                          r.Service,
		"environment":                      r.Environment,
		"test_title":                       r.TestTitle,
		"do_not_reactivate":                strconv.FormatBool(r.DoNotReactivate),
	}
	if r.ProductTypeName != "" {
		fields["product_type_name"] = r.ProductTypeName
	}

	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return fmt.Errorf("writing field %s: %w", k, err)
		}
	}
	for _, tag := range r.Tags {
		if err := w.WriteField("tags", tag); err != nil {
			return fmt.Errorf("writing tag field: %w", err)
		}
	}

	fw, err := w.CreateFormFile("file", r.FileName)
	if err != nil {
		return fmt.Errorf("creating form file: %w", err)
	}
	if _, err := fw.Write(r.FileBody); err != nil {
		return fmt.Errorf("writing file body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("closing multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v2/reimport-scan/", body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("reimport-scan request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reimport-scan returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
