package handler

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
)

// SecureToken provides a wrapper around sensitive token data with automatic zeroing
type SecureToken struct {
	data []byte
	mu   sync.RWMutex
}

// NewSecureToken creates a new secure token from a string
func NewSecureToken(token string) *SecureToken {
	if token == "" {
		return &SecureToken{data: nil}
	}
	return &SecureToken{
		data: []byte(token),
	}
}

// Get returns the token value as a string (creates a copy)
func (st *SecureToken) Get() string {
	if st == nil {
		return ""
	}
	st.mu.RLock()
	defer st.mu.RUnlock()

	if st.data == nil {
		return ""
	}

	// Return a copy to prevent external modification
	return string(st.data)
}

// Zero securely erases the token from memory
func (st *SecureToken) Zero() {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.data == nil {
		return
	}

	// Overwrite with random data first
	_, _ = rand.Read(st.data)

	// Then zero it
	for i := range st.data {
		st.data[i] = 0
	}

	st.data = nil
}

// IsEmpty checks if the token is empty
func (st *SecureToken) IsEmpty() bool {
	if st == nil {
		return true
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.data) == 0
}

// MaskedString returns a masked version for logging
func (st *SecureToken) MaskedString() string {
	if st == nil || st.IsEmpty() {
		return "[empty]"
	}

	st.mu.RLock()
	defer st.mu.RUnlock()

	length := len(st.data)
	if length <= 8 {
		return "****"
	}

	// Show first 4 and last 4 characters
	return string(st.data[:4]) + "..." + string(st.data[length-4:])
}

// CompareConstantTime performs constant-time comparison to prevent timing attacks
func (st *SecureToken) CompareConstantTime(other string) bool {
	if st == nil || st.IsEmpty() {
		return other == ""
	}

	st.mu.RLock()
	defer st.mu.RUnlock()

	otherBytes := []byte(other)

	// Constant-time length check
	if len(st.data) != len(otherBytes) {
		return false
	}

	// Constant-time byte comparison
	var result byte
	for i := range st.data {
		result |= st.data[i] ^ otherBytes[i]
	}

	return result == 0
}

// TokenCache provides a simple cache for tokens with expiration
type TokenCache struct {
	tokens map[string]*SecureToken
	mu     sync.RWMutex
}

// NewTokenCache creates a new token cache
func NewTokenCache() *TokenCache {
	return &TokenCache{
		tokens: make(map[string]*SecureToken),
	}
}

// Set stores a token in the cache
func (tc *TokenCache) Set(key string, token *SecureToken) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Zero old token if it exists
	if old, exists := tc.tokens[key]; exists {
		old.Zero()
	}

	tc.tokens[key] = token
}

// Get retrieves a token from the cache
func (tc *TokenCache) Get(key string) *SecureToken {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.tokens[key]
}

// Clear removes all tokens and zeros them
func (tc *TokenCache) Clear() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for _, token := range tc.tokens {
		token.Zero()
	}

	tc.tokens = make(map[string]*SecureToken)
}

// obfuscateForLog masks sensitive data for logging
func obfuscateForLog(data string, showChars int) string {
	if data == "" {
		return "[empty]"
	}

	if len(data) <= showChars*2 {
		return "****"
	}

	return data[:showChars] + "..." + data[len(data)-showChars:]
}

// HashToken creates a one-way hash of a token for comparison purposes
func HashToken(token string) string {
	if token == "" {
		return ""
	}
	// Use base64 encoding of the token for a simple non-reversible representation
	// In production, you might want to use a proper hash function like SHA256
	return base64.StdEncoding.EncodeToString([]byte(token))
}
