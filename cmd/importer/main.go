// SPDX-License-Identifier: GPL-3.0-or-later

// Command importer watches trivy-operator report CRDs and forwards them to
// DefectDojo, assigning product type and product name using rules specific
// to this deployment (see internal/mapping).
package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/config"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/defectdojo"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/k8s"
	"github.com/yoshz/trivy-operator-defectdojo-importer/internal/metrics"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	setLogLevel(cfg.LogLevel)
	slog.Info("starting trivy-operator-defectdojo-importer",
		"reports", cfg.Reports, "defectDojoURL", cfg.DefectDojoURL)

	restConfig, err := k8s.BuildRestConfig()
	if err != nil {
		slog.Error("building kubernetes client config", "error", err)
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		slog.Error("building kubernetes clientset", "error", err)
		os.Exit(1)
	}

	dynClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		slog.Error("building kubernetes dynamic client", "error", err)
		os.Exit(1)
	}

	httpClient := &http.Client{Timeout: 60 * time.Second}
	if cfg.HTTPProxy != "" || cfg.HTTPSProxy != "" {
		httpClient.Transport = proxyTransport(cfg.HTTPProxy, cfg.HTTPSProxy)
	}
	ddClient := defectdojo.New(cfg.DefectDojoURL, cfg.DefectDojoAPIKey, httpClient)

	controller := k8s.NewController(cfg, dynClient, clientset, ddClient)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("serving metrics", "addr", cfg.MetricsAddr)
		if err := metrics.Serve(cfg.MetricsAddr); err != nil {
			slog.Error("metrics server exited", "error", err)
		}
	}()

	if err := controller.Run(ctx); err != nil {
		slog.Error("controller exited with error", "error", err)
		os.Exit(1)
	}
}

func proxyTransport(httpProxy, httpsProxy string) *http.Transport {
	return &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			raw := httpProxy
			if req.URL.Scheme == "https" {
				raw = httpsProxy
			}
			if raw == "" {
				return nil, nil
			}
			return url.Parse(raw)
		},
	}
}

func setLogLevel(level string) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}
