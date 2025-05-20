package auth

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{
			name:  "Long value",
			value: strings.Repeat("a", 64),
		},
		{
			name:  "Short value",
			value: "a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{
				"Authorization": []string{fmt.Sprintf("ApiKey %s", tt.value)},
			}
			key, err := GetAPIKey(header)
			if err != nil {
				t.Fatal(err)
			}
			if key != tt.value {
				t.Errorf("expected %s, got %s", tt.value, key)
			}
		})
	}
}

func TestGetAPIKey_Error(t *testing.T) {
	tests := []struct {
		name     string
		value    [2]string
		expected string
	}{
		{
			name:     "Missing header",
			value:    [2]string{"x-Auth", "ApiKey two"},
			expected: "no authorization header included",
		},
		{
			name:     "Different header",
			value:    [2]string{"Authorization", "Baerer key"},
			expected: "malformed authorization header",
		},
		{
			name:     "Missing key",
			value:    [2]string{"Authorization", "ApiKey"},
			expected: "malformed authorization header",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetAPIKey(http.Header{
				tt.value[0]: []string{tt.value[1]},
			})
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if err.Error() != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, err.Error())
			}
		})
	}
}
