package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_validateURLParam(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid (basic)",
			input: "/books?page=2",
		},
		{
			name:  "valid (boolean and flags)",
			input: "/books?page=2",
		},
		{
			name:  "valid (multiple parameters)",
			input: "/filter?category=action&rating=5",
		},
		{
			name:  "valid (date and time)",
			input: "/events?from=2025-01-01&to=2025-01-31",
		},
		{
			name:    "invalid (no space allowed)",
			input:   "/events?from=2025 01 01&to=2025-01-31",
			wantErr: true,
		},
		{
			name:    "invalid (unicode not allowed)",
			input:   "/events?from=2025🤠01&to=2025-01-31",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		err := validateURLParam(tc.input)
		if tc.wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func Test_parseURLQueryInt(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{
			name:  "valid query",
			input: "564",
			want:  564,
		},
		{
			name:  "negative query",
			input: "-34",
			want:  34,
		},
		{
			name:    "float query",
			input:   "4.453",
			wantErr: true,
		},
		{
			name:    "letters query",
			input:   "wejrwj",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		got, err := parseURLQueryInt(tc.input)
		if tc.wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		}
	}
}

func Test_formatId(t *testing.T) {
	got := formatId("userexample", "randomid")
	want := "userexample:randomid"
	require.Equal(t, want, got)
}

func Test_generateKeys(t *testing.T) {
	email := "test@example.com"
	username := "johnnytest34"
	expected := map[string]string{
		"973dfe463ec8": "cd7e97b3ff27",
		"d7294d2ad4d4": "cd7e97b3ff27",
	}
	got := generateKeys(email, username)
	require.Equal(t, expected, got)
}
