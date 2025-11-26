package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

const longtitle = "opnwyt264 45325hg swtwt2 252525dwtw 235234652 twtwvsfgsgs35234t"

func Test_isValidUsername(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid username",
			input: "nooblord10",
		},
		{
			name:    "invalid length (too long)",
			input:   "342kerk12222222444444",
			wantErr: true,
		},
		{
			name:    "invalid length (too short)",
			input:   "32w4",
			wantErr: true,
		},
		{
			name:    "invalid character type",
			input:   "322#$rwqt",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		err := isValidUsername(tc.input)
		if tc.wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func Test_IsValidKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid email key",
			input: "random123@gmail.com",
		},
		{
			name:  "valid username",
			input: "randomuser34",
		},
		{
			name:    "invalid key (malformed email)",
			input:   "b:h@gmail.com",
			wantErr: true,
		},
		{
			name:    "invalid key (malformed username)",
			input:   ";;;username",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		err := IsValidKey(tc.input)
		if tc.wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func Test_isValidPassword(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid password",
			input: "randomPassword@23!",
		},
		{
			name:    "invalid password (too short)",
			input:   "etrwe",
			wantErr: true,
		},
		{
			name:    "invalid password (too long)",
			input:   "etrw333333333333333333333e",
			wantErr: true,
		},
		{
			name:    "invalid password (no digit)",
			input:   "randompassWord",
			wantErr: true,
		},
		{
			name:    "invalid password (no uppercase)",
			input:   "etrwe34wwwwwwrw",
			wantErr: true,
		},
		{
			name:    "invalid password (no lowercase)",
			input:   "WWWWWRW#$#4556",
			wantErr: true,
		},
		{
			name:    "invalid password (invalid unicode)",
			input:   "randomPass!🤠2",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		err := IsValidPassword(tc.input)
		if tc.wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func Test_IsValidTitle(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid",
			input: "My New Title",
		},
		{
			name:    "invalid (too short)",
			input:   "w",
			wantErr: true,
		},
		{
			name:    "invalid (too long)",
			input:   longtitle,
			wantErr: true,
		},
		{
			name:    "invalid (invalid character 🤠)",
			input:   "My New Title 🤠",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		err := IsValidTitle(tc.input)
		if tc.wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func Test_GetRefreshToken(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		want    string
		wantErr bool
		errType error
	}{
		{
			name: "valid header",
			header: http.Header{
				"X-Refresh-Token": []string{"oet4256"},
			},
			want: "oet4256",
		},
		{
			name:    "no header included",
			header:  http.Header{},
			wantErr: true,
			errType: ErrNoRefreshTokenIncluded,
		},
		{
			name: "no header included (empty)",
			header: http.Header{
				"X-Refresh-Token": []string{},
			},
			wantErr: true,
			errType: ErrNoRefreshTokenIncluded,
		},
	}
	for _, tc := range tests {
		got, err := GetRefreshToken(tc.header)
		if tc.wantErr {
			require.Error(t, err)
			require.ErrorIs(t, err, ErrNoRefreshTokenIncluded)
		} else {
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		}
	}
}

func Test_getBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		input   http.Header
		want    string
		wantErr bool
		errType error
	}{
		{
			name: "valid bearer token",
			input: http.Header{
				"Authorization": []string{"Bearer example"},
			},
			want: "example",
		},
		{
			name:    "invalid (empty auth header)",
			input:   http.Header{},
			wantErr: true,
			errType: ErrNoAuthHeaderIncluded,
		},
		{
			name: "invalid (malformed header)",
			input: http.Header{
				"Authorization": []string{"bearertoken"},
			},
			wantErr: true,
			errType: ErrMalformedAuth,
		},
		{
			name: "invalid (invalid header)",
			input: http.Header{
				"Auth": []string{"bearer token"},
			},
			wantErr: true,
			errType: ErrNoAuthHeaderIncluded,
		},
	}
	for _, tc := range tests {
		got, err := getBearerToken(tc.input)
		if tc.wantErr {
			require.Error(t, err)
			require.ErrorIs(t, err, tc.errType)
		} else {
			require.NoError(t, err)
			require.Equal(t, got, tc.want)
		}
	}
}

/*
func Test_RegisterValidation(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		email    string
		wantErr  bool
	}{
		{},
	}
}
*/
