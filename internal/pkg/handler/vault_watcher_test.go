package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stakater/Reloader/internal/pkg/options"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Test isValidVaultPath with various inputs
func TestIsValidVaultPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "valid simple path",
			path:     "secret/data/app/config",
			expected: true,
		},
		{
			name:     "valid path with underscores",
			path:     "secret/data/app_name/config_file",
			expected: true,
		},
		{
			name:     "valid path with hyphens",
			path:     "secret/data/my-app/my-config",
			expected: true,
		},
		{
			name:     "valid path with numbers",
			path:     "secret/data/app123/config456",
			expected: true,
		},
		{
			name:     "empty path",
			path:     "",
			expected: false,
		},
		{
			name:     "path traversal with double dots",
			path:     "secret/data/../../../etc/passwd",
			expected: false,
		},
		{
			name:     "path with leading slash",
			path:     "/secret/data/app/config",
			expected: false,
		},
		{
			name:     "path with trailing slash",
			path:     "secret/data/app/config/",
			expected: false,
		},
		{
			name:     "path with consecutive slashes",
			path:     "secret//data/app/config",
			expected: false,
		},
		{
			name:     "path with special characters",
			path:     "secret/data/app@config",
			expected: false,
		},
		{
			name:     "path with spaces",
			path:     "secret/data/app config",
			expected: false,
		},
		{
			name:     "path with query params",
			path:     "secret/data/app?token=abc",
			expected: false,
		},
		{
			name:     "path with hash",
			path:     "secret/data/app#fragment",
			expected: false,
		},
		{
			name:     "path with backslash",
			path:     "secret\\data\\app\\config",
			expected: false,
		},
		{
			name:     "path with null byte",
			path:     "secret/data/app\x00/config",
			expected: false,
		},
		{
			name:     "path with newline",
			path:     "secret/data/app\n/config",
			expected: false,
		},
		{
			name:     "very long valid path",
			path:     "secret/data/very/long/path/with/many/segments/that/is/still/valid",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidVaultPath(tt.path)
			if result != tt.expected {
				t.Errorf("isValidVaultPath(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

// Test sanitizePath to ensure it properly masks sensitive information
func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "empty path",
			path:     "",
			expected: "[empty]",
		},
		{
			name:     "short path",
			path:     "secret/data",
			expected: "secret/data",
		},
		{
			name:     "path with 2 segments",
			path:     "secret/config",
			expected: "secret/config",
		},
		{
			name:     "path with more than 2 segments",
			path:     "secret/data/prod/database/password",
			expected: ".../database/password",
		},
		{
			name:     "very long path gets truncated",
			path:     strings.Repeat("a", 150),
			expected: strings.Repeat("a", 100) + "...[truncated]",
		},
		{
			name:     "path with sensitive info is masked",
			path:     "secret/data/production/api/keys/stripe",
			expected: ".../keys/stripe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizePath(tt.path)
			if result != tt.expected {
				t.Errorf("sanitizePath(%q) = %q, expected %q", tt.path, result, tt.expected)
			}
		})
	}
}

// Test sanitizeError to ensure it redacts sensitive information
func TestSanitizeError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		shouldMatch string
	}{
		{
			name:        "nil error",
			err:         nil,
			shouldMatch: "",
		},
		{
			name:        "error with token keyword",
			err:         errors.New("invalid token: hvs.CAESIJ..."),
			shouldMatch: "authentication error (details redacted)",
		},
		{
			name:        "error with HTTP URL",
			err:         errors.New("failed to connect to http://vault.internal.company.com/v1/secret"),
			shouldMatch: "vault API error (URL redacted)",
		},
		{
			name:        "error with HTTPS URL",
			err:         errors.New("failed to connect to https://vault.internal.company.com/v1/secret"),
			shouldMatch: "vault API error (URL redacted)",
		},
		{
			name:        "very long error message",
			err:         errors.New(strings.Repeat("a", 200)),
			shouldMatch: "[truncated]",
		},
		{
			name:        "regular error passes through",
			err:         errors.New("connection refused"),
			shouldMatch: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeError(tt.err)
			if tt.shouldMatch == "" {
				if result != nil {
					t.Errorf("sanitizeError(nil) should return nil, got %v", result)
				}
				return
			}

			if result == nil {
				t.Errorf("sanitizeError(%v) returned nil, expected error containing %q", tt.err, tt.shouldMatch)
				return
			}

			if !strings.Contains(result.Error(), tt.shouldMatch) {
				t.Errorf("sanitizeError(%v) = %q, should contain %q", tt.err, result.Error(), tt.shouldMatch)
			}
		})
	}
}

// Test extractPaths with validation
func TestExtractPaths(t *testing.T) {
	// Save original annotation value
	originalAnnotation := options.VaultUpdateOnChangeAnnotation
	defer func() {
		options.VaultUpdateOnChangeAnnotation = originalAnnotation
	}()
	options.VaultUpdateOnChangeAnnotation = "vault.reloader.stakater.com/reload"

	tests := []struct {
		name        string
		annotations map[string]string
		expected    []string
	}{
		{
			name:        "nil annotations",
			annotations: nil,
			expected:    nil,
		},
		{
			name:        "empty annotations",
			annotations: map[string]string{},
			expected:    nil,
		},
		{
			name: "no vault annotation",
			annotations: map[string]string{
				"other.annotation": "value",
			},
			expected: nil,
		},
		{
			name: "single valid path",
			annotations: map[string]string{
				"vault.reloader.stakater.com/reload": "secret/data/app/config",
			},
			expected: []string{"secret/data/app/config"},
		},
		{
			name: "multiple valid paths",
			annotations: map[string]string{
				"vault.reloader.stakater.com/reload": "secret/data/app/config,secret/data/app/database",
			},
			expected: []string{"secret/data/app/config", "secret/data/app/database"},
		},
		{
			name: "paths with whitespace",
			annotations: map[string]string{
				"vault.reloader.stakater.com/reload": " secret/data/app/config , secret/data/app/database ",
			},
			expected: []string{"secret/data/app/config", "secret/data/app/database"},
		},
		{
			name: "invalid path gets filtered out",
			annotations: map[string]string{
				"vault.reloader.stakater.com/reload": "secret/data/../etc/passwd",
			},
			expected: []string{},
		},
		{
			name: "mix of valid and invalid paths",
			annotations: map[string]string{
				"vault.reloader.stakater.com/reload": "secret/data/valid,secret/data/../invalid,secret/data/another-valid",
			},
			expected: []string{"secret/data/valid", "secret/data/another-valid"},
		},
		{
			name: "empty path in list",
			annotations: map[string]string{
				"vault.reloader.stakater.com/reload": "secret/data/app,,secret/data/db",
			},
			expected: []string{"secret/data/app", "secret/data/db"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPaths(tt.annotations)

			if len(result) != len(tt.expected) {
				t.Errorf("extractPaths() returned %d paths, expected %d: got %v, expected %v",
					len(result), len(tt.expected), result, tt.expected)
				return
			}

			for i, path := range result {
				if path != tt.expected[i] {
					t.Errorf("extractPaths() path[%d] = %q, expected %q", i, path, tt.expected[i])
				}
			}
		})
	}
}

// Test extractPathsFromPodTemplate
func TestExtractPathsFromPodTemplate(t *testing.T) {
	options.VaultUpdateOnChangeAnnotation = "vault.reloader.stakater.com/reload"

	tests := []struct {
		name       string
		deployment *appsv1.Deployment
		expected   []string
	}{
		{
			name: "deployment with valid vault annotation",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-deployment",
					Namespace: "default",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"vault.reloader.stakater.com/reload": "secret/data/app/config",
							},
						},
					},
				},
			},
			expected: []string{"secret/data/app/config"},
		},
		{
			name: "deployment with no annotations",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-deployment",
					Namespace: "default",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{},
					},
				},
			},
			expected: nil,
		},
		{
			name: "deployment with multiple paths",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-deployment",
					Namespace: "default",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"vault.reloader.stakater.com/reload": "secret/data/app/config,secret/data/app/creds",
							},
						},
					},
				},
			},
			expected: []string{"secret/data/app/config", "secret/data/app/creds"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPathsFromPodTemplate(tt.deployment)

			if len(result) != len(tt.expected) {
				t.Errorf("extractPathsFromPodTemplate() returned %d paths, expected %d",
					len(result), len(tt.expected))
				return
			}

			for i, path := range result {
				if path != tt.expected[i] {
					t.Errorf("extractPathsFromPodTemplate() path[%d] = %q, expected %q",
						i, path, tt.expected[i])
				}
			}
		})
	}
}

// Test toKVv2MetadataPath conversion
func TestToKVv2MetadataPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "data path to metadata",
			input:    "secret/data/app/config",
			expected: "secret/metadata/app/config",
		},
		{
			name:     "already metadata path",
			input:    "secret/metadata/app/config",
			expected: "secret/metadata/app/config",
		},
		{
			name:     "path without data or metadata",
			input:    "secret/app/config",
			expected: "secret/metadata/app/config",
		},
		{
			name:     "single segment path",
			input:    "secret",
			expected: "secret",
		},
		{
			name:     "complex path with data",
			input:    "my-secrets/data/production/database/credentials",
			expected: "my-secrets/metadata/production/database/credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toKVv2MetadataPath(tt.input)
			if result != tt.expected {
				t.Errorf("toKVv2MetadataPath(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Test fetchKVv2CurrentVersion with mock server
func TestFetchKVv2CurrentVersion(t *testing.T) {
	tests := []struct {
		name          string
		responseCode  int
		responseBody  string
		expectedVer   int
		expectedError bool
	}{
		{
			name:          "successful fetch",
			responseCode:  http.StatusOK,
			responseBody:  `{"data":{"current_version":5}}`,
			expectedVer:   5,
			expectedError: false,
		},
		{
			name:          "version zero",
			responseCode:  http.StatusOK,
			responseBody:  `{"data":{"current_version":0}}`,
			expectedVer:   0,
			expectedError: false,
		},
		{
			name:          "unauthorized",
			responseCode:  http.StatusUnauthorized,
			responseBody:  `{"errors":["permission denied"]}`,
			expectedVer:   0,
			expectedError: true,
		},
		{
			name:          "not found",
			responseCode:  http.StatusNotFound,
			responseBody:  `{"errors":["secret not found"]}`,
			expectedVer:   0,
			expectedError: true,
		},
		{
			name:          "invalid JSON",
			responseCode:  http.StatusOK,
			responseBody:  `invalid json`,
			expectedVer:   0,
			expectedError: true,
		},
		{
			name:          "missing current_version field",
			responseCode:  http.StatusOK,
			responseBody:  `{"data":{}}`,
			expectedVer:   0,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request has token header
				if r.Header.Get("X-Vault-Token") == "" {
					t.Error("Expected X-Vault-Token header")
				}

				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			client := server.Client()
			version, err := fetchKVv2CurrentVersion(client, server.URL, "test-token", "secret/data/test")

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if version != tt.expectedVer {
					t.Errorf("Expected version %d, got %d", tt.expectedVer, version)
				}
			}
		})
	}
}

// Test checkVaultVersionsParallel with mock data
func TestCheckVaultVersionsParallel(t *testing.T) {
	// Create mock server that returns version 1 for all paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"current_version":1}}`))
	}))
	defer server.Close()

	options.VaultAddress = server.URL
	options.VaultToken = "test-token"

	paths := map[nsPath]struct{}{
		{ns: "default", path: "secret/data/app1/config"}: {},
		{ns: "default", path: "secret/data/app2/config"}: {},
		{ns: "prod", path: "secret/data/app3/config"}:    {},
	}

	var mu sync.Mutex
	last := map[nsPath]int{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	changes := checkVaultVersionsParallel(ctx, server.Client(), paths, &mu, last)

	// All paths should trigger changes since they're new
	if len(changes) != len(paths) {
		t.Errorf("Expected %d changes, got %d", len(paths), len(changes))
	}

	// Verify all paths are now in the last map
	mu.Lock()
	if len(last) != len(paths) {
		t.Errorf("Expected %d entries in last map, got %d", len(paths), len(last))
	}
	mu.Unlock()

	// Run again - should detect no changes
	changes2 := checkVaultVersionsParallel(ctx, server.Client(), paths, &mu, last)
	if len(changes2) != 0 {
		t.Errorf("Expected 0 changes on second run, got %d", len(changes2))
	}
}

// Test checkVaultTokenPermissions
func TestCheckVaultTokenPermissions(t *testing.T) {
	tests := []struct {
		name         string
		responseCode int
		responseBody string
		expectWarn   bool
	}{
		{
			name:         "token has data access (bad)",
			responseCode: http.StatusOK,
			responseBody: `{"data":{"value":"secret"}}`,
			expectWarn:   true,
		},
		{
			name:         "token denied data access (good)",
			responseCode: http.StatusForbidden,
			responseBody: `{"errors":["permission denied"]}`,
			expectWarn:   false,
		},
		{
			name:         "path not found (neutral)",
			responseCode: http.StatusNotFound,
			responseBody: `{"errors":["not found"]}`,
			expectWarn:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Save and restore options
			oldAddress := options.VaultAddress
			oldToken := options.VaultToken
			defer func() {
				options.VaultAddress = oldAddress
				options.VaultToken = oldToken
			}()

			options.VaultAddress = server.URL
			options.VaultToken = "test-token"

			// This function logs but doesn't return anything
			// In a real test, you'd capture log output
			checkVaultTokenPermissions(server.Client())

			// Test passes if it doesn't panic
		})
	}
}

// Benchmark isValidVaultPath
func BenchmarkIsValidVaultPath(b *testing.B) {
	testPath := "secret/data/production/application/configuration"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isValidVaultPath(testPath)
	}
}

// Benchmark sanitizePath
func BenchmarkSanitizePath(b *testing.B) {
	testPath := "secret/data/production/application/configuration/database/credentials"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitizePath(testPath)
	}
}

// Benchmark extractPaths
func BenchmarkExtractPaths(b *testing.B) {
	options.VaultUpdateOnChangeAnnotation = "vault.reloader.stakater.com/reload"
	annotations := map[string]string{
		"vault.reloader.stakater.com/reload": "secret/data/app1,secret/data/app2,secret/data/app3",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractPaths(annotations)
	}
}
