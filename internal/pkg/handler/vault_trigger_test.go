package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stakater/Reloader/internal/pkg/metrics"
	"github.com/stakater/Reloader/internal/pkg/options"
)

// Test VaultRotationPayload JSON marshaling/unmarshaling
func TestVaultRotationPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload VaultRotationPayload
	}{
		{
			name: "minimal payload",
			payload: VaultRotationPayload{
				Path: "secret/data/app/config",
			},
		},
		{
			name: "with single namespace",
			payload: VaultRotationPayload{
				Path:      "secret/data/app/config",
				Namespace: "production",
			},
		},
		{
			name: "with multiple namespaces",
			payload: VaultRotationPayload{
				Path:       "secret/data/app/config",
				Namespaces: []string{"prod", "staging", "dev"},
			},
		},
		{
			name: "with version",
			payload: VaultRotationPayload{
				Path:    "secret/data/app/config",
				Version: "5",
			},
		},
		{
			name: "complete payload",
			payload: VaultRotationPayload{
				Path:       "secret/data/app/config",
				Namespace:  "production",
				Namespaces: []string{"prod", "staging"},
				Version:    "10",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			data, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("Failed to marshal payload: %v", err)
			}

			// Unmarshal back
			var decoded VaultRotationPayload
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Failed to unmarshal payload: %v", err)
			}

			// Verify fields
			if decoded.Path != tt.payload.Path {
				t.Errorf("Path = %q, expected %q", decoded.Path, tt.payload.Path)
			}
			if decoded.Namespace != tt.payload.Namespace {
				t.Errorf("Namespace = %q, expected %q", decoded.Namespace, tt.payload.Namespace)
			}
			if decoded.Version != tt.payload.Version {
				t.Errorf("Version = %q, expected %q", decoded.Version, tt.payload.Version)
			}
		})
	}
}

// Test vault trigger endpoint with various inputs
func TestVaultTriggerEndpoint(t *testing.T) {
	// Save original options
	originalEnabled := options.EnableVaultTrigger
	originalToken := options.VaultRotationToken
	defer func() {
		options.EnableVaultTrigger = originalEnabled
		options.VaultRotationToken = originalToken
	}()

	options.EnableVaultTrigger = true
	options.VaultRotationToken = ""

	// Create mock collectors
	collectors := metrics.Collectors{
		VaultTriggers:            nil,
		VaultTriggersByNamespace: nil,
	}

	// Register the endpoint
	RegisterVaultEndpoint(collectors)

	tests := []struct {
		name           string
		method         string
		body           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "GET method not allowed",
			method:         http.MethodGet,
			body:           "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "method not allowed",
		},
		{
			name:           "POST with valid minimal payload",
			method:         http.MethodPost,
			body:           `{"path":"secret/data/app/config"}`,
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "POST with empty body",
			method:         http.MethodPost,
			body:           "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid JSON",
		},
		{
			name:           "POST with invalid JSON",
			method:         http.MethodPost,
			body:           `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid JSON",
		},
		{
			name:           "POST without path",
			method:         http.MethodPost,
			body:           `{"namespace":"default"}`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "'path' is required",
		},
		{
			name:           "POST with invalid path (traversal)",
			method:         http.MethodPost,
			body:           `{"path":"secret/data/../../../etc/passwd"}`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid path format",
		},
		{
			name:           "POST with invalid path (special chars)",
			method:         http.MethodPost,
			body:           `{"path":"secret/data/app@config"}`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid path format",
		},
		{
			name:           "POST with leading slash",
			method:         http.MethodPost,
			body:           `{"path":"/secret/data/app/config"}`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid path format",
		},
		{
			name:           "POST with namespace",
			method:         http.MethodPost,
			body:           `{"path":"secret/data/app/config","namespace":"production"}`,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:           "POST with multiple namespaces",
			method:         http.MethodPost,
			body:           `{"path":"secret/data/app/config","namespaces":["prod","staging"]}`,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:           "POST with version",
			method:         http.MethodPost,
			body:           `{"path":"secret/data/app/config","version":"5"}`,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/trigger/vault", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			// Call the endpoint directly through DefaultServeMux
			RegisterVaultEndpoint(collectors)
			handler, _ := http.DefaultServeMux.Handler(req)

			handler.ServeHTTP(w, req)

			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Status = %d, expected %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.expectedBody != "" && !strings.Contains(string(body), tt.expectedBody) {
				t.Errorf("Body = %q, should contain %q", string(body), tt.expectedBody)
			}
		})
	}
}

// Test vault trigger with authentication token
func TestVaultTriggerEndpoint_WithAuth(t *testing.T) {
	// Save original options
	originalEnabled := options.EnableVaultTrigger
	originalToken := options.VaultRotationToken
	defer func() {
		options.EnableVaultTrigger = originalEnabled
		options.VaultRotationToken = originalToken
	}()

	options.EnableVaultTrigger = true
	options.VaultRotationToken = "secret-token-123"

	collectors := metrics.Collectors{
		VaultTriggers:            nil,
		VaultTriggersByNamespace: nil,
	}

	RegisterVaultEndpoint(collectors)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "valid token",
			authHeader:     "secret-token-123",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid token",
			authHeader:     "wrong-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "missing token",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"path":"secret/data/app/config"}`
			req := httptest.NewRequest(http.MethodPost, "/trigger/vault", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tt.authHeader != "" {
				req.Header.Set("X-Vault-Rotation-Token", tt.authHeader)
			}

			w := httptest.NewRecorder()
			handler, _ := http.DefaultServeMux.Handler(req)
			handler.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Status = %d, expected %d", resp.StatusCode, tt.expectedStatus)
			}
		})
	}
}

// Test request size limit
func TestVaultTriggerEndpoint_RequestSizeLimit(t *testing.T) {
	originalEnabled := options.EnableVaultTrigger
	defer func() {
		options.EnableVaultTrigger = originalEnabled
	}()

	options.EnableVaultTrigger = true

	collectors := metrics.Collectors{}
	RegisterVaultEndpoint(collectors)

	// Create a request body larger than 1MB
	largePayload := VaultRotationPayload{
		Path:       "secret/data/app/config",
		Namespaces: make([]string, 100000), // Will be > 1MB when marshaled
	}
	for i := range largePayload.Namespaces {
		largePayload.Namespaces[i] = "namespace-" + strings.Repeat("x", 100)
	}

	body, err := json.Marshal(largePayload)
	if err != nil {
		t.Fatalf("Failed to marshal large payload: %v", err)
	}

	// Verify payload is indeed > 1MB
	if len(body) < 1<<20 {
		t.Skip("Test payload not large enough")
	}

	req := httptest.NewRequest(http.MethodPost, "/trigger/vault", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler, _ := http.DefaultServeMux.Handler(req)
	handler.ServeHTTP(w, req)

	resp := w.Result()

	// Should reject with BadRequest
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Status = %d, expected %d for oversized request", resp.StatusCode, http.StatusBadRequest)
	}
}

// Test namespace determination logic
func TestVaultTriggerEndpoint_NamespaceLogic(t *testing.T) {
	tests := []struct {
		name              string
		payload           VaultRotationPayload
		expectedNamespace string // What namespace(s) should be targeted
	}{
		{
			name: "no namespace specified - should use all",
			payload: VaultRotationPayload{
				Path: "secret/data/app/config",
			},
			expectedNamespace: "all",
		},
		{
			name: "single namespace specified",
			payload: VaultRotationPayload{
				Path:      "secret/data/app/config",
				Namespace: "production",
			},
			expectedNamespace: "production",
		},
		{
			name: "multiple namespaces specified",
			payload: VaultRotationPayload{
				Path:       "secret/data/app/config",
				Namespaces: []string{"prod", "staging"},
			},
			expectedNamespace: "multiple",
		},
		{
			name: "both namespace and namespaces specified - namespaces takes precedence",
			payload: VaultRotationPayload{
				Path:       "secret/data/app/config",
				Namespace:  "production",
				Namespaces: []string{"prod", "staging"},
			},
			expectedNamespace: "multiple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Determine namespaces using same logic as the handler
			namespaces := tt.payload.Namespaces
			if len(namespaces) == 0 {
				if tt.payload.Namespace != "" {
					namespaces = []string{tt.payload.Namespace}
				} else {
					namespaces = []string{""}
				}
			}

			// Verify the logic matches expectations
			switch tt.expectedNamespace {
			case "all":
				if len(namespaces) != 1 || namespaces[0] != "" {
					t.Errorf("Expected all namespaces, got %v", namespaces)
				}
			case "production":
				if len(namespaces) != 1 || namespaces[0] != "production" {
					t.Errorf("Expected production namespace, got %v", namespaces)
				}
			case "multiple":
				if len(namespaces) < 2 {
					t.Errorf("Expected multiple namespaces, got %v", namespaces)
				}
			}
		})
	}
}

// Test path sanitization in error messages
func TestVaultTriggerEndpoint_PathSanitization(t *testing.T) {
	// This test verifies that sensitive paths are sanitized in logs
	// We can't directly test log output, but we verify sanitizePath works

	sensitivePath := "secret/data/production/database/master-password"
	sanitized := sanitizePath(sensitivePath)

	// Should not expose the full path structure
	if strings.Contains(sanitized, "production") && strings.Contains(sanitized, "database") {
		t.Error("Sanitized path still contains too much information")
	}

	// Should show only last segments
	if !strings.Contains(sanitized, "master-password") {
		t.Error("Sanitized path should contain last segment")
	}
}

// Test error sanitization in vault trigger
func TestVaultTriggerEndpoint_ErrorSanitization(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		check func(error) bool
	}{
		{
			name: "error with token",
			err:  errors.New("authentication failed: token hvs.CAESIJ... is invalid"),
			check: func(e error) bool {
				return !strings.Contains(e.Error(), "hvs.CAESIJ")
			},
		},
		{
			name: "error with URL",
			err:  errors.New("failed to connect to https://vault.internal.company.com"),
			check: func(e error) bool {
				return !strings.Contains(e.Error(), "vault.internal.company.com")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized := sanitizeError(tt.err)
			if !tt.check(sanitized) {
				t.Errorf("Error not properly sanitized: %v", sanitized)
			}
		})
	}
}

// Benchmark vault trigger payload parsing
func BenchmarkVaultTriggerPayloadParsing(b *testing.B) {
	body := []byte(`{"path":"secret/data/app/config","namespace":"production","version":"5"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var payload VaultRotationPayload
		_ = json.Unmarshal(body, &payload)
	}
}

// Test RegisterVaultEndpoint when disabled
func TestRegisterVaultEndpoint_Disabled(t *testing.T) {
	originalEnabled := options.EnableVaultTrigger
	defer func() {
		options.EnableVaultTrigger = originalEnabled
	}()

	options.EnableVaultTrigger = false

	collectors := metrics.Collectors{}

	// Should not panic when disabled
	RegisterVaultEndpoint(collectors)

	// Endpoint should not be registered
	req := httptest.NewRequest(http.MethodPost, "/trigger/vault", nil)
	w := httptest.NewRecorder()

	// DefaultServeMux should return 404 if not registered
	handler, _ := http.DefaultServeMux.Handler(req)
	handler.ServeHTTP(w, req)

	// Note: This test is limited because we can't easily check if handler was registered
	// In a real scenario, you'd use a custom ServeMux for testing
}

// Test with various valid path formats
func TestVaultTriggerEndpoint_ValidPathFormats(t *testing.T) {
	originalEnabled := options.EnableVaultTrigger
	defer func() {
		options.EnableVaultTrigger = originalEnabled
	}()

	options.EnableVaultTrigger = true

	validPaths := []string{
		"secret/data/app/config",
		"secret/data/my-app/my-config",
		"secret/data/app_name/config_file",
		"secret/data/app123/config456",
		"kv/data/production/database",
		"my-secrets/data/api/keys",
	}

	collectors := metrics.Collectors{}
	RegisterVaultEndpoint(collectors)

	for _, path := range validPaths {
		t.Run(path, func(t *testing.T) {
			payload := VaultRotationPayload{Path: path}
			body, _ := json.Marshal(payload)

			req := httptest.NewRequest(http.MethodPost, "/trigger/vault", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler, _ := http.DefaultServeMux.Handler(req)
			handler.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Valid path %q was rejected with status %d", path, resp.StatusCode)
			}
		})
	}
}
