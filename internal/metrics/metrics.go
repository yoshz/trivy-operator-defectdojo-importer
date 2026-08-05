// SPDX-License-Identifier: GPL-3.0-or-later

// Package metrics exposes Prometheus metrics for the importer, served on
// /metrics, mirroring the original operator's requests_total counter.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "requests_total",
		Help: "DefectDojo import requests processed, by outcome.",
	}, []string{"status"})

	ProcessingSeconds = promauto.NewSummary(prometheus.SummaryOpts{
		Name: "request_processing_seconds",
		Help: "Time spent processing a report and sending it to DefectDojo.",
	})
)

// Serve starts the metrics HTTP server. It blocks until the server exits.
func Serve(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return http.ListenAndServe(addr, mux)
}
