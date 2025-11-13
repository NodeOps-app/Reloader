package handler

import (
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/sirupsen/logrus"

    "github.com/stakater/Reloader/internal/pkg/metrics"
    "github.com/stakater/Reloader/internal/pkg/options"
    "github.com/stakater/Reloader/pkg/common"
    "github.com/stakater/Reloader/pkg/kube"

    appsv1 "k8s.io/api/apps/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// nsPath is a compound key for (namespace, vault-path)
type nsPath struct{ ns, path string }

// StartVaultWatcher starts a background goroutine that periodically:
// 1) Discovers annotated workloads and their namespaces
// 2) Polls Vault KV v2 metadata current_version for each distinct (namespace, path)
// 3) Triggers rolling upgrades when a version change is detected
// It avoids any external webhook and does not require creating Kubernetes Secrets.
func StartVaultWatcher(collectors metrics.Collectors) {
    if !options.EnableVaultWatcher {
        return
    }
    if options.VaultAddress == "" {
        logrus.Warn("Vault watcher enabled but vault-address not set; watcher will be inactive")
        return
    }

    // Resolve token from flag or environment variable VAULT_TOKEN (or VAULT_TOKEN_FILE)
    effectiveToken := options.VaultToken
    if effectiveToken == "" {
        if tf := os.Getenv("VAULT_TOKEN_FILE"); tf != "" {
            if b, err := os.ReadFile(tf); err == nil {
                effectiveToken = strings.TrimSpace(string(b))
            } else {
                logrus.Warnf("vault watcher: failed reading VAULT_TOKEN_FILE: %v", err)
            }
        }
    }
    if effectiveToken == "" {
        effectiveToken = os.Getenv("VAULT_TOKEN")
    }
    if effectiveToken == "" {
        logrus.Warn("Vault watcher enabled but no token provided via --vault-token, VAULT_TOKEN, or VAULT_TOKEN_FILE; watcher will be inactive")
        return
    }

    interval, err := time.ParseDuration(options.VaultPollInterval)
    if err != nil || interval <= 0 {
        logrus.Warnf("Invalid vault-poll-interval '%s', defaulting to 30s", options.VaultPollInterval)
        interval = 30 * time.Second
    }

    // HTTP client for Vault
    tr := &http.Transport{}
    if strings.HasPrefix(strings.ToLower(options.VaultAddress), "https://") {
        tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: options.VaultInsecureSkipTLSVerify} // #nosec G402 - opt-in via flag
    }
    httpClient := &http.Client{Timeout: 10 * time.Second, Transport: tr}

    // Cache of last seen version per namespace+path
    var mu sync.Mutex
    last := map[nsPath]int{}

    go func() {
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        for {
            if err := evaluateOnce(httpClient, effectiveToken, collectors, &mu, last); err != nil {
                logrus.Debugf("vault watcher iteration error: %v", err)
            }
            <-ticker.C
        }
    }()

    logrus.Infof("Vault watcher started: address=%s interval=%s", options.VaultAddress, interval.String())
}

func evaluateOnce(httpClient *http.Client, token string, collectors metrics.Collectors, mu *sync.Mutex, last map[nsPath]int) error {
    clients := kube.GetClients()
    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
    defer cancel()

    // Discover annotated paths from workloads
    workloads := 0
    paths := map[nsPath]struct{}{}

    // Deployments
    if dList, err := clients.KubernetesClient.AppsV1().Deployments("").List(ctx, metav1.ListOptions{}); err == nil {
        for i := range dList.Items {
            workloads++
            ns := dList.Items[i].Namespace
            for _, p := range extractPathsFromPodTemplate(&dList.Items[i]) {
                paths[nsPath{ns, p}] = struct{}{}
            }
        }
    }
    // StatefulSets
    if ssList, err := clients.KubernetesClient.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{}); err == nil {
        for i := range ssList.Items {
            workloads++
            ns := ssList.Items[i].Namespace
            for _, p := range extractPathsFromPodTemplateSS(&ssList.Items[i]) {
                paths[nsPath{ns, p}] = struct{}{}
            }
        }
    }
    // DaemonSets
    if dsList, err := clients.KubernetesClient.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{}); err == nil {
        for i := range dsList.Items {
            workloads++
            ns := dsList.Items[i].Namespace
            for _, p := range extractPathsFromPodTemplateDS(&dsList.Items[i]) {
                paths[nsPath{ns, p}] = struct{}{}
            }
        }
    }

    if len(paths) == 0 {
        logrus.Debug("vault watcher: no annotated workloads discovered in this iteration")
        return nil
    }

    // Check Vault version for each ns+path
    for k := range paths {
        version, err := fetchKVv2CurrentVersion(httpClient, options.VaultAddress, token, k.path)
        if err != nil {
            logrus.Debugf("vault watcher: failed to fetch version for path=%s ns=%s: %v", k.path, k.ns, err)
            continue
        }

        mu.Lock()
        prev, found := last[k]
        if !found || version != prev {
            last[k] = version
            mu.Unlock()
            // Trigger rollout
            cfg := common.GetVaultConfig(k.ns, k.path, fmt.Sprintf("%d", version))
            if err := doRollingUpgrade(cfg, collectors, nil, invokeReloadStrategy); err != nil {
                logrus.Errorf("vault watcher: upgrade failed for path '%s' ns '%s': %v", k.path, k.ns, err)
                if collectors.VaultTriggers != nil {
                    collectors.VaultTriggers.WithLabelValues("false").Inc()
                }
                if collectors.VaultTriggersByNamespace != nil {
                    collectors.VaultTriggersByNamespace.WithLabelValues("false", k.ns).Inc()
                }
            } else {
                if collectors.VaultTriggers != nil {
                    collectors.VaultTriggers.WithLabelValues("true").Inc()
                }
                if collectors.VaultTriggersByNamespace != nil {
                    collectors.VaultTriggersByNamespace.WithLabelValues("true", k.ns).Inc()
                }
                logrus.Infof("vault watcher: triggered rollout for path='%s' ns='%s' version=%d", k.path, k.ns, version)
            }
        } else {
            mu.Unlock()
        }
    }

    logrus.Debugf("vault watcher: scanned %d workloads, tracked %d path-ns pairs", workloads, len(paths))
    return nil
}

// extractPathsFromPodTemplate extracts comma-separated annotation values from the Vault annotation key for a Deployment
func extractPathsFromPodTemplate(dep *appsv1.Deployment) []string {
    return extractPaths(dep.Spec.Template.Annotations)
}

func extractPathsFromPodTemplateSS(ss *appsv1.StatefulSet) []string {
    return extractPaths(ss.Spec.Template.Annotations)
}

func extractPathsFromPodTemplateDS(ds *appsv1.DaemonSet) []string {
    return extractPaths(ds.Spec.Template.Annotations)
}

func extractPaths(annotations map[string]string) []string {
    if annotations == nil {
        return nil
    }
    val, ok := annotations[options.VaultUpdateOnChangeAnnotation]
    if !ok || strings.TrimSpace(val) == "" {
        return nil
    }
    values := strings.Split(val, ",")
    out := make([]string, 0, len(values))
    for _, v := range values {
        v = strings.TrimSpace(v)
        if v != "" {
            out = append(out, v)
        }
    }
    return out
}

// fetchKVv2CurrentVersion queries Vault KV v2 metadata endpoint for the provided annotation path (e.g., secret/data/a/b)
// and returns the current_version integer.
func fetchKVv2CurrentVersion(httpClient *http.Client, addr, token, annotationPath string) (int, error) {
    metaPath := toKVv2MetadataPath(annotationPath)
    url := strings.TrimRight(addr, "/") + "/v1/" + metaPath
    req, err := http.NewRequest(http.MethodGet, url, nil)
    if err != nil {
        return 0, err
    }
    if token != "" {
        req.Header.Set("X-Vault-Token", token)
    }
    resp, err := httpClient.Do(req)
    if err != nil {
        return 0, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return 0, fmt.Errorf("vault metadata get failed: status=%d", resp.StatusCode)
    }
    var body struct {
        Data struct {
            CurrentVersion int `json:"current_version"`
        } `json:"data"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
        return 0, err
    }
    return body.Data.CurrentVersion, nil
}

// toKVv2MetadataPath converts an annotation path like "secret/data/app/config" to
// the KV v2 metadata API path like "secret/metadata/app/config".
func toKVv2MetadataPath(annotationPath string) string {
    // Replace the first occurrence of "/data/" with "/metadata/". If not present, attempt a best-effort transform.
    if strings.Contains(annotationPath, "/data/") {
        return strings.Replace(annotationPath, "/data/", "/metadata/", 1)
    }
    // If already looks like metadata, pass-through
    if strings.Contains(annotationPath, "/metadata/") {
        return annotationPath
    }
    // Default: assume mount then append metadata segment after first component
    parts := strings.SplitN(annotationPath, "/", 2)
    if len(parts) == 2 {
        return parts[0] + "/metadata/" + parts[1]
    }
    return annotationPath
}
