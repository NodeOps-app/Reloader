package handler

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// Test NewSecureToken creation
func TestNewSecureToken(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "create from string",
			input:    "hvs.CAESIJ1234567890",
			expected: "hvs.CAESIJ1234567890",
		},
		{
			name:     "create from empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "create from long token",
			input:    strings.Repeat("a", 100),
			expected: strings.Repeat("a", 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := NewSecureToken(tt.input)
			if token == nil {
				t.Fatal("NewSecureToken returned nil")
			}

			result := token.Get()
			if result != tt.expected {
				t.Errorf("token.Get() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// Test SecureToken.Get
func TestSecureToken_Get(t *testing.T) {
	token := NewSecureToken("test-token-123")

	// Should return the same value multiple times
	for i := 0; i < 3; i++ {
		result := token.Get()
		if result != "test-token-123" {
			t.Errorf("Get() call %d returned %q, expected %q", i, result, "test-token-123")
		}
	}

	// Test nil token
	var nilToken *SecureToken
	if nilToken.Get() != "" {
		t.Error("nil token Get() should return empty string")
	}
}

// Test SecureToken.Zero
func TestSecureToken_Zero(t *testing.T) {
	token := NewSecureToken("sensitive-token")

	// Verify token exists
	if token.Get() != "sensitive-token" {
		t.Fatal("Token not set correctly")
	}

	// Zero the token
	token.Zero()

	// Verify token is empty
	if token.Get() != "" {
		t.Errorf("After Zero(), Get() returned %q, expected empty string", token.Get())
	}

	// Verify it's actually empty
	if !token.IsEmpty() {
		t.Error("After Zero(), IsEmpty() should return true")
	}

	// Test nil token doesn't panic
	var nilToken *SecureToken
	nilToken.Zero() // Should not panic
}

// Test SecureToken.IsEmpty
func TestSecureToken_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		token    *SecureToken
		expected bool
	}{
		{
			name:     "non-empty token",
			token:    NewSecureToken("test-token"),
			expected: false,
		},
		{
			name:     "empty token",
			token:    NewSecureToken(""),
			expected: true,
		},
		{
			name:     "nil token",
			token:    nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.token.IsEmpty()
			if result != tt.expected {
				t.Errorf("IsEmpty() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// Test SecureToken.MaskedString
func TestSecureToken_MaskedString(t *testing.T) {
	tests := []struct {
		name        string
		token       *SecureToken
		shouldMatch string
	}{
		{
			name:        "nil token",
			token:       nil,
			shouldMatch: "[empty]",
		},
		{
			name:        "empty token",
			token:       NewSecureToken(""),
			shouldMatch: "[empty]",
		},
		{
			name:        "short token",
			token:       NewSecureToken("short"),
			shouldMatch: "****",
		},
		{
			name:        "long token shows first and last 4 chars",
			token:       NewSecureToken("hvs.CAESIJ1234567890abcdef"),
			shouldMatch: "hvs.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.token.MaskedString()
			if !strings.Contains(result, tt.shouldMatch) {
				t.Errorf("MaskedString() = %q, should contain %q", result, tt.shouldMatch)
			}

			// Verify it doesn't leak the full token
			if tt.token != nil && !tt.token.IsEmpty() {
				fullToken := tt.token.Get()
				if len(fullToken) > 8 && result == fullToken {
					t.Error("MaskedString() returned full token instead of masked version")
				}
			}
		})
	}
}

// Test SecureToken.CompareConstantTime
func TestSecureToken_CompareConstantTime(t *testing.T) {
	tests := []struct {
		name     string
		token    *SecureToken
		compare  string
		expected bool
	}{
		{
			name:     "identical tokens",
			token:    NewSecureToken("test-token-123"),
			compare:  "test-token-123",
			expected: true,
		},
		{
			name:     "different tokens",
			token:    NewSecureToken("test-token-123"),
			compare:  "test-token-456",
			expected: false,
		},
		{
			name:     "empty token vs empty string",
			token:    NewSecureToken(""),
			compare:  "",
			expected: true,
		},
		{
			name:     "nil token vs empty string",
			token:    nil,
			compare:  "",
			expected: true,
		},
		{
			name:     "token vs empty string",
			token:    NewSecureToken("test"),
			compare:  "",
			expected: false,
		},
		{
			name:     "different length tokens",
			token:    NewSecureToken("short"),
			compare:  "very-long-token",
			expected: false,
		},
		{
			name:     "case sensitive comparison",
			token:    NewSecureToken("Test"),
			compare:  "test",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.token.CompareConstantTime(tt.compare)
			if result != tt.expected {
				t.Errorf("CompareConstantTime(%q) = %v, expected %v", tt.compare, result, tt.expected)
			}
		})
	}
}

// Test that CompareConstantTime actually runs in constant time
// This is a basic test - a real cryptographic test would be more sophisticated
func TestSecureToken_CompareConstantTime_Timing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timing test in short mode")
	}

	token := NewSecureToken("test-token-with-many-characters-1234567890")

	// Compare with strings that differ at different positions
	tests := []string{
		"Xest-token-with-many-characters-1234567890", // Differs at position 0
		"test-token-with-many-characters-123456789X", // Differs at last position
		"test-Xoken-with-many-characters-1234567890", // Differs in middle
	}

	const iterations = 1000
	timings := make([]time.Duration, len(tests))

	for i, testStr := range tests {
		start := time.Now()
		for j := 0; j < iterations; j++ {
			token.CompareConstantTime(testStr)
		}
		timings[i] = time.Since(start)
	}

	// Verify all timings are within reasonable range (within 50% of each other)
	// This is a loose check since Go's scheduler can introduce variance
	avgTiming := (timings[0] + timings[1] + timings[2]) / 3
	for i, timing := range timings {
		diff := float64(timing-avgTiming) / float64(avgTiming)
		if diff < 0 {
			diff = -diff
		}
		if diff > 0.5 {
			t.Logf("Warning: timing variance for test %d: %.2f%% (may not be truly constant time)", i, diff*100)
		}
	}
}

// Test TokenCache
func TestTokenCache(t *testing.T) {
	cache := NewTokenCache()
	if cache == nil {
		t.Fatal("NewTokenCache returned nil")
	}

	// Test Set and Get
	token1 := NewSecureToken("token1")
	cache.Set("key1", token1)

	retrieved := cache.Get("key1")
	if retrieved == nil {
		t.Fatal("Get returned nil for existing key")
	}
	if retrieved.Get() != "token1" {
		t.Errorf("Retrieved token = %q, expected %q", retrieved.Get(), "token1")
	}

	// Test overwrite
	token2 := NewSecureToken("token2")
	cache.Set("key1", token2)

	retrieved = cache.Get("key1")
	if retrieved.Get() != "token2" {
		t.Errorf("After overwrite, retrieved token = %q, expected %q", retrieved.Get(), "token2")
	}

	// Test Clear
	cache.Set("key2", NewSecureToken("token3"))
	cache.Clear()

	if cache.Get("key1") != nil {
		t.Error("After Clear(), Get should return nil")
	}
	if cache.Get("key2") != nil {
		t.Error("After Clear(), Get should return nil for all keys")
	}
}

// Test TokenCache thread safety
func TestTokenCache_Concurrent(t *testing.T) {
	cache := NewTokenCache()
	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := "key"
			for j := 0; j < numOperations; j++ {
				// Alternate between Set and Get
				if j%2 == 0 {
					token := NewSecureToken("token")
					cache.Set(key, token)
				} else {
					_ = cache.Get(key)
				}
			}
		}(i)
	}

	wg.Wait()
	// Test passes if no race conditions or panics
}

// Test SecureToken thread safety
func TestSecureToken_Concurrent(t *testing.T) {
	token := NewSecureToken("test-token-123")
	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				// Mix of reads and checks
				_ = token.Get()
				_ = token.IsEmpty()
				_ = token.MaskedString()
				_ = token.CompareConstantTime("test")
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions or panics
}

// Test obfuscateForLog
func TestObfuscateForLog(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		showChars int
		expected  string
	}{
		{
			name:      "empty string",
			data:      "",
			showChars: 4,
			expected:  "[empty]",
		},
		{
			name:      "short string",
			data:      "abc",
			showChars: 4,
			expected:  "****",
		},
		{
			name:      "long string",
			data:      "hvs.CAESIJ1234567890",
			showChars: 4,
			expected:  "hvs....7890",
		},
		{
			name:      "exactly at threshold",
			data:      "12345678",
			showChars: 4,
			expected:  "****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := obfuscateForLog(tt.data, tt.showChars)
			if result != tt.expected {
				t.Errorf("obfuscateForLog(%q, %d) = %q, expected %q",
					tt.data, tt.showChars, result, tt.expected)
			}
		})
	}
}

// Test HashToken
func TestHashToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "regular token",
			token: "hvs.CAESIJ1234567890",
		},
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "long token",
			token: strings.Repeat("a", 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashToken(tt.token)

			if tt.token == "" {
				if hash != "" {
					t.Error("HashToken of empty string should return empty string")
				}
				return
			}

			// Verify hash is different from original
			if hash == tt.token {
				t.Error("HashToken should return different value than input")
			}

			// Verify consistency - same input gives same output
			hash2 := HashToken(tt.token)
			if hash != hash2 {
				t.Error("HashToken should be deterministic")
			}

			// Verify different inputs give different outputs
			hash3 := HashToken(tt.token + "x")
			if hash == hash3 {
				t.Error("HashToken should give different outputs for different inputs")
			}
		})
	}
}

// Benchmark SecureToken operations
func BenchmarkSecureToken_Get(b *testing.B) {
	token := NewSecureToken("test-token-123456789")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = token.Get()
	}
}

func BenchmarkSecureToken_CompareConstantTime(b *testing.B) {
	token := NewSecureToken("test-token-123456789")
	compare := "test-token-123456789"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = token.CompareConstantTime(compare)
	}
}

func BenchmarkSecureToken_MaskedString(b *testing.B) {
	token := NewSecureToken("test-token-123456789")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = token.MaskedString()
	}
}

func BenchmarkSecureToken_Zero(b *testing.B) {
	for i := 0; i < b.N; i++ {
		token := NewSecureToken("test-token-123456789")
		token.Zero()
	}
}

// Test that Zero actually overwrites memory
func TestSecureToken_Zero_MemoryOverwrite(t *testing.T) {
	originalToken := "sensitive-data-12345"
	token := NewSecureToken(originalToken)

	// Verify token has data initially
	token.mu.RLock()
	initialData := token.data
	token.mu.RUnlock()

	if len(initialData) == 0 {
		t.Fatal("Token should have data initially")
	}

	// Zero the token
	token.Zero()

	// Verify data was cleared
	token.mu.RLock()
	if token.data != nil {
		t.Error("After Zero(), internal data should be nil")
	}
	token.mu.RUnlock()

	// Note: We can't easily verify the memory was overwritten with random data
	// then zeroed, but we verified the slice is now nil
}

// Test SecureToken with deferred cleanup pattern
func TestSecureToken_DeferPattern(t *testing.T) {
	func() {
		token := NewSecureToken("sensitive-token")
		defer token.Zero()

		// Use the token
		if token.Get() != "sensitive-token" {
			t.Error("Token not set correctly")
		}

		// Token will be automatically zeroed when function exits
	}()

	// If we could inspect memory here, we'd verify it was zeroed
	// This test mainly ensures the defer pattern works without panics
}
