// SPDX-License-Identifier: GPL-3.0-or-later

package k8s

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// BuildRestConfig returns an in-cluster config when running inside a Pod,
// falling back to the local kubeconfig for development.
func BuildRestConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not determine home directory for kubeconfig: %w", err)
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("building kubeconfig from %s: %w", kubeconfig, err)
	}
	return cfg, nil
}
