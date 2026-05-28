package prometheus

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// Name set by tokenprovider.AuthMiddleware; not exported by the SDK.
const googleAuthMiddlewareName = "GoogleAuthentication"

func TestGoogleAuthExtendOptions(t *testing.T) {
	pemKey := newTestRSAPrivateKey(t)
	validSAJSON := mustMarshalServiceAccount(t, map[string]string{
		"type":         "service_account",
		"client_email": "sa@example.iam.gserviceaccount.com",
		"token_uri":    "https://oauth2.googleapis.com/token",
		"private_key":  pemKey,
	})
	saMissingEmail := mustMarshalServiceAccount(t, map[string]string{
		"type":        "service_account",
		"token_uri":   "https://oauth2.googleapis.com/token",
		"private_key": pemKey,
	})
	const secretMarker = "super-secret-marker-must-not-leak"

	tests := []struct {
		name             string
		jsonData         string
		decryptedSecure  map[string]string
		wantMiddleware   bool
		wantErrSubstring string
	}{
		{
			name:           "feature disabled when jsonData is empty",
			jsonData:       "",
			wantMiddleware: false,
		},
		{
			name:           "feature disabled when googleAuthType is absent",
			jsonData:       `{"httpMethod":"POST"}`,
			wantMiddleware: false,
		},
		{
			name:           "feature disabled when googleAuthType is the empty string",
			jsonData:       `{"googleAuthType":""}`,
			wantMiddleware: false,
		},
		{
			name:           "ADC appends the Google auth middleware",
			jsonData:       `{"googleAuthType":"adc"}`,
			wantMiddleware: true,
		},
		{
			name:           "ADC tolerates other jsonData fields",
			jsonData:       `{"googleAuthType":"adc","httpMethod":"POST","customQueryParameters":"x=y"}`,
			wantMiddleware: true,
		},
		{
			name:             "unknown googleAuthType errors",
			jsonData:         `{"googleAuthType":"banana"}`,
			wantErrSubstring: `unsupported googleAuthType "banana"`,
		},
		{
			name:             "malformed jsonData errors",
			jsonData:         `{not json`,
			wantErrSubstring: "parsing jsonData",
		},
		{
			name:             "serviceAccountJson without secret errors",
			jsonData:         `{"googleAuthType":"serviceAccountJson"}`,
			wantErrSubstring: "Service Account JSON key is required",
		},
		{
			name:     "serviceAccountJson with valid key appends the middleware",
			jsonData: `{"googleAuthType":"serviceAccountJson"}`,
			decryptedSecure: map[string]string{
				secureKeyGoogleServiceAccountJSON: validSAJSON,
			},
			wantMiddleware: true,
		},
		{
			name:     "serviceAccountJson with malformed JSON errors without leaking input",
			jsonData: `{"googleAuthType":"serviceAccountJson"}`,
			decryptedSecure: map[string]string{
				secureKeyGoogleServiceAccountJSON: "this-is-not-json-" + secretMarker,
			},
			wantErrSubstring: "parsing service account JSON failed",
		},
		{
			name:     "serviceAccountJson with wrong type errors without leaking input",
			jsonData: `{"googleAuthType":"serviceAccountJson"}`,
			decryptedSecure: map[string]string{
				secureKeyGoogleServiceAccountJSON: `{"type":"user","client_email":"` + secretMarker + `"}`,
			},
			wantErrSubstring: "parsing service account JSON failed",
		},
		{
			name:     "serviceAccountJson missing client_email errors",
			jsonData: `{"googleAuthType":"serviceAccountJson"}`,
			decryptedSecure: map[string]string{
				secureKeyGoogleServiceAccountJSON: saMissingEmail,
			},
			wantErrSubstring: "missing client_email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := backend.DataSourceInstanceSettings{
				ID:                      42,
				Updated:                 time.Unix(1700000000, 0),
				JSONData:                []byte(tt.jsonData),
				DecryptedSecureJSONData: tt.decryptedSecure,
			}
			opts := &sdkhttpclient.Options{}
			err := googleAuthExtendOptions(context.Background(), settings, opts, log.DefaultLogger)

			if tt.wantErrSubstring != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSubstring)
				// Whatever the error, the raw secret must never appear in it.
				assert.NotContains(t, err.Error(), secretMarker)
				assert.Empty(t, opts.Middlewares, "no middleware should be appended on error")
				return
			}

			require.NoError(t, err)
			if tt.wantMiddleware {
				require.Len(t, opts.Middlewares, 1)
				assertGoogleAuthMiddleware(t, opts.Middlewares[0])
			} else {
				assert.Empty(t, opts.Middlewares)
			}
		})
	}
}

func TestGoogleAuthExtendOptions_PreservesExistingMiddlewares(t *testing.T) {
	existingA := sdkhttpclient.NamedMiddlewareFunc("existing-a", passthroughMiddleware)
	existingB := sdkhttpclient.NamedMiddlewareFunc("existing-b", passthroughMiddleware)

	opts := &sdkhttpclient.Options{
		Middlewares: []sdkhttpclient.Middleware{existingA, existingB},
	}
	settings := backend.DataSourceInstanceSettings{
		ID:       1,
		Updated:  time.Unix(1700000000, 0),
		JSONData: []byte(`{"googleAuthType":"adc"}`),
	}

	require.NoError(t, googleAuthExtendOptions(context.Background(), settings, opts, log.DefaultLogger))

	require.Len(t, opts.Middlewares, 3)
	assertNamedMiddleware(t, opts.Middlewares[0], "existing-a")
	assertNamedMiddleware(t, opts.Middlewares[1], "existing-b")
	assertGoogleAuthMiddleware(t, opts.Middlewares[2])
}

func TestExtendOptions_DelegatesToGoogleAuth(t *testing.T) {
	settings := backend.DataSourceInstanceSettings{
		ID:       1,
		Updated:  time.Unix(1700000000, 0),
		JSONData: []byte(`{"googleAuthType":"adc"}`),
	}
	opts := &sdkhttpclient.Options{}
	require.NoError(t, extendOptions(context.Background(), settings, opts, log.DefaultLogger))
	require.Len(t, opts.Middlewares, 1)
	assertGoogleAuthMiddleware(t, opts.Middlewares[0])
}

func TestExtendOptions_DisabledByDefault(t *testing.T) {
	opts := &sdkhttpclient.Options{}
	require.NoError(t, extendOptions(context.Background(),
		backend.DataSourceInstanceSettings{}, opts, log.DefaultLogger))
	assert.Empty(t, opts.Middlewares)
}

func TestGoogleAuthExtendOptions_EmptySettingsIsSafe(t *testing.T) {
	opts := &sdkhttpclient.Options{}
	err := googleAuthExtendOptions(context.Background(),
		backend.DataSourceInstanceSettings{}, opts, log.DefaultLogger)
	require.NoError(t, err)
	assert.Empty(t, opts.Middlewares)
}

// TestGoogleAuthExtendOptions_FromProvisioningYAML documents the YAML wire
// contract used by datasource provisioning. Renaming `googleAuthType` or
// `googleServiceAccountJson` is a backwards-incompatible change for users
// with existing provisioning files.
func TestGoogleAuthExtendOptions_FromProvisioningYAML(t *testing.T) {
	saJSON := mustMarshalServiceAccount(t, map[string]string{
		"type":         "service_account",
		"client_email": "sa@example.iam.gserviceaccount.com",
		"token_uri":    "https://oauth2.googleapis.com/token",
		"private_key":  newTestRSAPrivateKey(t),
	})

	// Mimics the shape of a single entry in conf/provisioning/datasources/*.yaml.
	type provisioningEntry struct {
		JSONData       map[string]any    `yaml:"jsonData"`
		SecureJSONData map[string]string `yaml:"secureJsonData"`
	}

	yamlText := `
jsonData:
  googleAuthType: serviceAccountJson
secureJsonData:
  googleServiceAccountJson: |
` + indent(saJSON, "    ")

	var entry provisioningEntry
	require.NoError(t, yaml.Unmarshal([]byte(yamlText), &entry))

	jsonData, err := json.Marshal(entry.JSONData)
	require.NoError(t, err)

	settings := backend.DataSourceInstanceSettings{
		ID:                      99,
		Updated:                 time.Unix(1700000000, 0),
		JSONData:                jsonData,
		DecryptedSecureJSONData: entry.SecureJSONData,
	}
	opts := &sdkhttpclient.Options{}
	require.NoError(t, googleAuthExtendOptions(context.Background(), settings, opts, log.DefaultLogger))
	require.Len(t, opts.Middlewares, 1)
	assertGoogleAuthMiddleware(t, opts.Middlewares[0])
}

func TestParseServiceAccountKey(t *testing.T) {
	pemKey := newTestRSAPrivateKey(t)

	t.Run("valid key", func(t *testing.T) {
		raw := mustMarshalServiceAccount(t, map[string]string{
			"type":         "service_account",
			"client_email": "sa@example.iam.gserviceaccount.com",
			"token_uri":    "https://oauth2.googleapis.com/token",
			"private_key":  pemKey,
		})
		cfg, err := parseServiceAccountKey([]byte(raw))
		require.NoError(t, err)
		assert.Equal(t, "sa@example.iam.gserviceaccount.com", cfg.Email)
		assert.Equal(t, "https://oauth2.googleapis.com/token", cfg.URI)
		assert.Equal(t, []byte(pemKey), cfg.PrivateKey)
	})

	t.Run("missing fields", func(t *testing.T) {
		raw := `{"type":"service_account"}`
		_, err := parseServiceAccountKey([]byte(raw))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing client_email")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := parseServiceAccountKey([]byte("not json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key file")
	})

	t.Run("wrong type", func(t *testing.T) {
		_, err := parseServiceAccountKey([]byte(`{"type":"user"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key file")
	})
}

func assertGoogleAuthMiddleware(t *testing.T, mw sdkhttpclient.Middleware) {
	t.Helper()
	assertNamedMiddleware(t, mw, googleAuthMiddlewareName)
}

func assertNamedMiddleware(t *testing.T, mw sdkhttpclient.Middleware, want string) {
	t.Helper()
	named, ok := mw.(sdkhttpclient.MiddlewareName)
	require.True(t, ok, "middleware must implement MiddlewareName")
	assert.Equal(t, want, named.MiddlewareName())
}

func passthroughMiddleware(_ sdkhttpclient.Options, next http.RoundTripper) http.RoundTripper {
	return next
}

func newTestRSAPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return string(pemBytes)
}

func mustMarshalServiceAccount(t *testing.T, fields map[string]string) string {
	t.Helper()
	b, err := json.Marshal(fields)
	require.NoError(t, err)
	return string(b)
}

// indent prefixes every line of s with pad. Used to embed a multi-line JSON
// blob into a YAML literal-block scalar.
func indent(s, pad string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		b.WriteString(pad)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
