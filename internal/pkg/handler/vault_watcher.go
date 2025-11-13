package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
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
	if options.VaultAddress == "" || options.VaultToken == "" {
		logrus.Warn("Vault watcher enabled but vault-address or vault-token not set; watcher will be inactive")
		return
	}

	interval, err := time.ParseDuration(options.VaultPollInterval)
	if err != nil || interval <= 0 {
		logrus.Warnf("Invalid vault-poll-interval '%s', defaulting to 30s", options.VaultPollInterval)
		interval = 30 * time.Second
	}

	// HTTP client for Vault with optimized connection pooling

	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}
	if strings.HasPrefix(strings.ToLower(options.VaultAddress), "https://") {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: options.VaultInsecureSkipTLSVerify} // #nosec G402 - opt-in via flag
	}
	httpClient := &http.Client{Timeout: 10 * time.Second, Transport: tr}

	// Check if token has data access and warn (should only have metadata access)
	checkVaultTokenPermissions(httpClient)

	// Cache of last seen version per namespace+path
	var mu sync.Mutex
	last := map[nsPath]int{}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			if err := evaluateOnce(httpClient, collectors, &mu, last); err != nil {
				logrus.Debugf("vault watcher iteration error: %v", err)
			}
			<-ticker.C
		}
	}()

	logrus.Infof("Vault watcher started: address=%s interval=%s", options.VaultAddress, interval.String())
}

func evaluateOnce(httpClient *http.Client, collectors metrics.Collectors, mu *sync.Mutex, last map[nsPath]int) error {
	clients := kube.GetClients()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Discover annotated paths from workloads using parallel fetching
	paths := discoverAnnotatedWorkloadsParallel(ctx, clients)

	if len(paths) == 0 {
		logrus.Debug("vault watcher: no annotated workloads discovered in this iteration")
		return nil
	}

	// Batch check Vault versions using worker pool
	versionChanges := checkVaultVersionsParallel(ctx, httpClient, paths, mu, last)

	// Process version changes and trigger rollouts
	for _, change := range versionChanges {
		cfg := common.GetVaultConfig(change.ns, change.path, fmt.Sprintf("%d", change.newVersion))
		if err := doRollingUpgrade(cfg, collectors, nil, invokeReloadStrategy); err != nil {
			logrus.Errorf("vault watcher: upgrade failed for path '%s' ns '%s': %v", sanitizePath(change.path), change.ns, err)
			if collectors.VaultTriggers != nil {
				collectors.VaultTriggers.WithLabelValues("false").Inc()
			}
			if collectors.VaultTriggersByNamespace != nil {
				collectors.VaultTriggersByNamespace.WithLabelValues("false", change.ns).Inc()
			}
		} else {
			if collectors.VaultTriggers != nil {
				collectors.VaultTriggers.WithLabelValues("true").Inc()
			}
			if collectors.VaultTriggersByNamespace != nil {
				collectors.VaultTriggersByNamespace.WithLabelValues("true", change.ns).Inc()
			}
			logrus.Infof("vault watcher: triggered rollout for path='%s' ns='%s' version=%d", sanitizePath(change.path), change.ns, change.newVersion)
		}
	}

	logrus.Debugf("vault watcher: tracked %d path-ns pairs, detected %d changes", len(paths), len(versionChanges))
	return nil
}

// workloadDiscovery holds result from discovering workloads
type workloadDiscovery struct {
	paths     map[nsPath]struct{}
	workloads int
	err       error
}

// discoverAnnotatedWorkloadsParallel fetches Deployments, StatefulSets, and DaemonSets in parallel

func discoverAnnotatedWorkloadsParallel(ctx context.Context, clients kube.Clients) map[nsPath]struct{} {
	var wg sync.WaitGroup
	results := make(chan workloadDiscovery, 3)

	// Fetch Deployments
	wg.Add(1)
	go func() {
		defer wg.Done()
		paths := make(map[nsPath]struct{})
		workloads := 0
		dList, err := clients.KubernetesClient.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
		if err != nil {
			logrus.Warnf("vault watcher: failed to list deployments: %v", err)
			results <- workloadDiscovery{paths: paths, workloads: 0, err: err}
			return
		}
		for i := range dList.Items {
			workloads++
			ns := dList.Items[i].Namespace
			for _, p := range extractPathsFromPodTemplate(&dList.Items[i]) {
				paths[nsPath{ns, p}] = struct{}{}
			}
		}
		results <- workloadDiscovery{paths: paths, workloads: workloads, err: nil}
	}()

	// Fetch StatefulSets
	wg.Add(1)
	go func() {
		defer wg.Done()
		paths := make(map[nsPath]struct{})
		workloads := 0
		ssList, err := clients.KubernetesClient.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			logrus.Warnf("vault watcher: failed to list statefulsets: %v", err)
			results <- workloadDiscovery{paths: paths, workloads: 0, err: err}
			return
		}
		for i := range ssList.Items {
			workloads++
			ns := ssList.Items[i].Namespace
			for _, p := range extractPathsFromPodTemplateSS(&ssList.Items[i]) {
				paths[nsPath{ns, p}] = struct{}{}
			}
		}
		results <- workloadDiscovery{paths: paths, workloads: workloads, err: nil}
	}()

	// Fetch DaemonSets
	wg.Add(1)
	go func() {
		defer wg.Done()
		paths := make(map[nsPath]struct{})
		workloads := 0
		dsList, err := clients.KubernetesClient.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			logrus.Warnf("vault watcher: failed to list daemonsets: %v", err)
			results <- workloadDiscovery{paths: paths, workloads: 0, err: err}
			return
		}
		for i := range dsList.Items {
			workloads++
			ns := dsList.Items[i].Namespace
			for _, p := range extractPathsFromPodTemplateDS(&dsList.Items[i]) {
				paths[nsPath{ns, p}] = struct{}{}
			}
		}
		results <- workloadDiscovery{paths: paths, workloads: workloads, err: nil}
	}()

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Merge results
	merged := make(map[nsPath]struct{})
	for result := range results {
		for k := range result.paths {
			merged[k] = struct{}{}
		}
	}

	return merged
}

// versionChange represents a detected version change
type versionChange struct {
	ns         string
	path       string
	newVersion int
}

// checkVaultVersionsParallel checks Vault versions for all paths using a worker pool

func checkVaultVersionsParallel(ctx context.Context, httpClient *http.Client, paths map[nsPath]struct{}, mu *sync.Mutex, last map[nsPath]int) []versionChange {
	const maxWorkers = 10 // Limit concurrent Vault API calls

	pathsChan := make(chan nsPath, len(paths))
	changesChan := make(chan versionChange, len(paths))

	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range pathsChan {
				version, err := fetchKVv2CurrentVersion(httpClient, options.VaultAddress, options.VaultToken, k.path)
				if err != nil {
					logrus.Debugf("vault watcher: failed to fetch version for path=%s ns=%s: %v", sanitizePath(k.path), k.ns, sanitizeError(err))
					continue
				}

				// Check if version changed - minimize time mutex is held
				mu.Lock()
				prev, found := last[k]
				shouldTrigger := !found || version != prev
				if shouldTrigger {
					last[k] = version
				}
				mu.Unlock()

				if shouldTrigger {
					changesChan <- versionChange{ns: k.ns, path: k.path, newVersion: version}
				}
			}
		}()
	}

	// Feed work to workers
	for k := range paths {
		pathsChan <- k
	}
	close(pathsChan)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(changesChan)
	}()

	// Collect changes
	changes := []versionChange{}
	for change := range changesChan {
		changes = append(changes, change)
	}

	return changes
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
	// Pre-allocate with estimated capacity
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {

			if !isValidVaultPath(v) {
				logrus.Warnf("vault watcher: invalid vault path detected and skipped: %s", sanitizePath(v))
				continue
			}
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

// isValidVaultPath validates that a Vault path conforms to allowed patterns
func isValidVaultPath(path string) bool {
	if path == "" {
		return false
	}

	// Prevent path traversal attacks
	if strings.Contains(path, "..") {
		return false
	}

	// Only allow alphanumeric, forward slash, underscore, hyphen
	for _, r := range path {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '/' || r == '_' || r == '-') {
			return false
		}
	}

	// Don't allow paths starting or ending with /
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return false
	}

	// Don't allow consecutive slashes
	if strings.Contains(path, "//") {
		return false
	}

	return true
}

// sanitizePath removes potentially sensitive information from paths for logging
func sanitizePath(path string) string {
	if path == "" {
		return "[empty]"
	}

	// Limit length to prevent log injection
	const maxLen = 100
	if len(path) > maxLen {
		return path[:maxLen] + "...[truncated]"
	}

	// Show only the last two segments to avoid exposing full internal structure
	parts := strings.Split(path, "/")
	if len(parts) > 2 {
		return ".../" + parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}

	return path
}

// sanitizeError removes sensitive information from error messages
func sanitizeError(err error) error {
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	// Remove potential tokens from error messages
	if strings.Contains(strings.ToLower(errMsg), "token") {
		return fmt.Errorf("authentication error (details redacted)")
	}

	// Remove full URLs that might contain sensitive query params
	if strings.Contains(errMsg, "http://") || strings.Contains(errMsg, "https://") {
		return fmt.Errorf("vault API error (URL redacted): connection or access issue")
	}

	// Limit error message length
	const maxErrLen = 150
	if len(errMsg) > maxErrLen {
		return fmt.Errorf("%s...[truncated]", errMsg[:maxErrLen])
	}

	return err
}

// checkVaultTokenPermissions validates that the Vault token only has metadata access
// and warns if it has data access (security best practice)
func checkVaultTokenPermissions(httpClient *http.Client) {
	if options.VaultToken == "" || options.VaultAddress == "" {
		return
	}

	// Try to access a common secret path to test permissions
	testPath := "secret/data/test-reloader-permissions-check"
	url := strings.TrimRight(options.VaultAddress, "/") + "/v1/" + testPath

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logrus.Debugf("vault watcher: unable to create permission check request: %v", err)
		return
	}

	req.Header.Set("X-Vault-Token", options.VaultToken)

	// Use short timeout for this check
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection errors are expected and don't indicate a problem
		logrus.Debugf("vault watcher: permission check request failed (expected): %v", sanitizeError(err))
		return
	}
	defer resp.Body.Close()

	// If we get 200 or 403, the token has capabilities on data paths
	if resp.StatusCode == http.StatusOK {
		logrus.Warn("⚠️  SECURITY WARNING: Vault token has READ access to secret DATA paths. For security, the token should ONLY have access to METADATA endpoints. Current setup: token can read actual secret values, which is unnecessary and increases security risk. Please restrict token to metadata-only permissions.")
	} else if resp.StatusCode == http.StatusForbidden {
		// This is actually good - means we can authenticate but don't have data access
		logrus.Info("vault watcher: token permissions verified - metadata-only access confirmed (no data path access)")
	}
	// 404 means the path doesn't exist, which is fine
	// Other status codes are inconclusive
}
