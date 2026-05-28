package prometheus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/grafana/grafana-google-sdk-go/pkg/tokenprovider"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"golang.org/x/oauth2/google"
)

const (
	googleAuthTypeNone               = ""
	googleAuthTypeADC                = "adc"
	googleAuthTypeServiceAccountJSON = "serviceAccountJson"

	// googleMonitoringReadScope is the OAuth scope used to query Google Cloud
	// monitoring data (incl. Google Managed Service for Prometheus). It matches
	// the scope used by the Cloud Monitoring data source — see
	// pkg/tsdb/cloud-monitoring/httpclient.go.
	googleMonitoringReadScope = "https://www.googleapis.com/auth/monitoring.read"

	secureKeyGoogleServiceAccountJSON = "googleServiceAccountJson"
)

// googleAuthJSONData is the subset of jsonData consumed by this file.
type googleAuthJSONData struct {
	GoogleAuthType string `json:"googleAuthType"`
}

// googleAuthExtendOptions appends a Google bearer-token middleware to the
// per-DS HTTP client when jsonData.googleAuthType is set to a supported
// value. Empty or absent googleAuthType is a no-op.
func googleAuthExtendOptions(
	_ context.Context,
	settings backend.DataSourceInstanceSettings,
	opts *sdkhttpclient.Options,
	_ log.Logger,
) error {
	var jd googleAuthJSONData
	if len(settings.JSONData) > 0 {
		if err := json.Unmarshal(settings.JSONData, &jd); err != nil {
			return fmt.Errorf("prometheus googleAuth: parsing jsonData: %w", err)
		}
	}

	switch jd.GoogleAuthType {
	case googleAuthTypeNone:
		return nil

	case googleAuthTypeADC:
		provider := tokenprovider.NewGceAccessTokenProvider(googleTokenProviderConfig(settings))
		opts.Middlewares = append(opts.Middlewares, tokenprovider.AuthMiddleware(provider))
		return nil

	case googleAuthTypeServiceAccountJSON:
		raw := settings.DecryptedSecureJSONData[secureKeyGoogleServiceAccountJSON]
		if raw == "" {
			return errors.New("A Service Account JSON key is required for Google Cloud Service Account JSON authentication")
		}
		jwtCfg, err := parseServiceAccountKey([]byte(raw))
		if err != nil {
			return err
		}
		cfg := googleTokenProviderConfig(settings)
		cfg.JwtTokenConfig = jwtCfg
		opts.Middlewares = append(opts.Middlewares, tokenprovider.AuthMiddleware(
			tokenprovider.NewJwtAccessTokenProvider(cfg),
		))
		return nil

	default:
		return fmt.Errorf("prometheus googleAuth: unsupported googleAuthType %q", jd.GoogleAuthType)
	}
}

// googleTokenProviderConfig builds the cache-keying config for the Google
// token provider. DataSourceID + Updated + Scopes form the cache key, so a
// data source edit invalidates the cached token automatically.
func googleTokenProviderConfig(settings backend.DataSourceInstanceSettings) tokenprovider.Config {
	return tokenprovider.Config{
		DataSourceID:      settings.ID,
		DataSourceUpdated: settings.Updated,
		Scopes:            []string{googleMonitoringReadScope},
	}
}

// parseServiceAccountKey parses a Google service-account JSON key and returns
// the fields needed by tokenprovider.JwtTokenConfig. Errors never include the
// raw key bytes.
func parseServiceAccountKey(raw []byte) (*tokenprovider.JwtTokenConfig, error) {
	jwtCfg, err := google.JWTConfigFromJSON(raw, googleMonitoringReadScope)
	if err != nil {
		return nil, errors.New("prometheus googleAuth: parsing service account JSON failed: invalid key file")
	}
	if jwtCfg.Email == "" || jwtCfg.TokenURL == "" || len(jwtCfg.PrivateKey) == 0 {
		return nil, errors.New("prometheus googleAuth: service account JSON is missing client_email, token_uri or private_key")
	}
	return &tokenprovider.JwtTokenConfig{
		Email:      jwtCfg.Email,
		URI:        jwtCfg.TokenURL,
		PrivateKey: jwtCfg.PrivateKey,
	}, nil
}
