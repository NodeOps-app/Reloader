package handler

import (
    "encoding/json"
    "io"
    "net/http"

    "github.com/sirupsen/logrus"
    "github.com/stakater/Reloader/internal/pkg/metrics"
    "github.com/stakater/Reloader/internal/pkg/options"
    "github.com/stakater/Reloader/pkg/common"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultRotationPayload defines the request body for triggering reloads on Vault secret rotation
type VaultRotationPayload struct {
    Path       string   `json:"path"`                 // Vault path identifier to match in workload annotation
    Namespace  string   `json:"namespace,omitempty"`  // Optional single namespace; empty means all namespaces
    Namespaces []string `json:"namespaces,omitempty"` // Optional list of namespaces to target
    Version    string   `json:"version,omitempty"`    // Optional version/nonce to vary the SHA
}

// RegisterVaultEndpoint registers the HTTP handler if enabled
func RegisterVaultEndpoint(collectors metrics.Collectors) {
    if !options.EnableVaultTrigger {
        return
    }
    http.HandleFunc("/trigger/vault", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }

        // Optional token validation
        if options.VaultRotationToken != "" {
            if r.Header.Get("X-Vault-Rotation-Token") != options.VaultRotationToken {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
        }

        body, err := io.ReadAll(r.Body)
        if err != nil {
            http.Error(w, "failed to read body", http.StatusBadRequest)
            return
        }
        defer r.Body.Close()

        var payload VaultRotationPayload
        if err := json.Unmarshal(body, &payload); err != nil {
            http.Error(w, "invalid JSON", http.StatusBadRequest)
            return
        }
        if payload.Path == "" {
            http.Error(w, "'path' is required", http.StatusBadRequest)
            return
        }

        // Determine namespaces to process
        namespaces := payload.Namespaces
        if len(namespaces) == 0 {
            if payload.Namespace != "" {
                namespaces = []string{payload.Namespace}
            } else {
                namespaces = []string{metav1.NamespaceAll}
            }
        }

        // Trigger reloads per targeted namespace
        failures := 0
        for _, ns := range namespaces {
            cfg := common.GetVaultConfig(ns, payload.Path, payload.Version)
            if options.WebhookUrl != "" {
                // If webhook-only mode is enabled, mimic existing behavior
                if err := sendUpgradeWebhook(cfg, options.WebhookUrl); err != nil {
                    logrus.Errorf("Vault trigger webhook failed for path '%s' ns '%s': %v", payload.Path, ns, err)
                    failures++
                    collectors.VaultTriggers.WithLabelValues("false").Inc()
                    collectors.VaultTriggersByNamespace.WithLabelValues("false", ns).Inc()
                }
                continue
            }
            if err := doRollingUpgrade(cfg, collectors, nil, invokeReloadStrategy); err != nil {
                logrus.Errorf("Vault trigger upgrade failed for path '%s' ns '%s': %v", payload.Path, ns, err)
                failures++
                collectors.VaultTriggers.WithLabelValues("false").Inc()
                collectors.VaultTriggersByNamespace.WithLabelValues("false", ns).Inc()
            } else {
                collectors.VaultTriggers.WithLabelValues("true").Inc()
                collectors.VaultTriggersByNamespace.WithLabelValues("true", ns).Inc()
            }
        }

        if failures > 0 {
            http.Error(w, "one or more namespaces failed", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"status":"ok"}`))
    })
    logrus.Infof("Vault trigger endpoint registered at /trigger/vault")
}
