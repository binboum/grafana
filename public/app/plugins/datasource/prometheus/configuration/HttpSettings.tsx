import { type ChangeEvent } from 'react';

import { type DataSourceSettings, type SelectableValue } from '@grafana/data';
import { Auth, AuthMethod, ConfigSection, ConnectionSettings, convertLegacyAuthProps } from '@grafana/plugin-ui';
import { docsTip, overhaulStyles, type PromOptions } from '@grafana/prometheus';
import { Alert, Field, SecretTextArea, SecureSocksProxySettings, Select, Stack, useTheme2 } from '@grafana/ui';

// Wire values for jsonData.googleAuthType. Empty string means disabled.
export const GoogleAuthType = {
  None: '',
  ADC: 'adc',
  ServiceAccountJSON: 'serviceAccountJson',
} as const;
type GoogleAuthTypeValue = (typeof GoogleAuthType)[keyof typeof GoogleAuthType];

// jsonData.googleAuthType and secureJsonData.googleServiceAccountJson are
// not declared in @grafana/prometheus's typed PromOptions — widen locally.
type PromOptionsWithGoogleAuth = PromOptions & {
  googleAuthType?: GoogleAuthTypeValue;
};
type PromSecureJsonData = {
  googleServiceAccountJson?: string;
};

const googleAuthOptions: Array<SelectableValue<GoogleAuthTypeValue>> = [
  { label: 'None', value: GoogleAuthType.None },
  {
    label: 'Google Cloud ADC',
    value: GoogleAuthType.ADC,
    description:
      'Use Application Default Credentials (metadata server or GOOGLE_APPLICATION_CREDENTIALS)',
  },
  {
    label: 'Service Account JSON',
    value: GoogleAuthType.ServiceAccountJSON,
    description: 'Use a service account JSON key',
  },
];

type Props = {
  options: DataSourceSettings<PromOptions>;
  onOptionsChange: (options: DataSourceSettings<PromOptions>) => void;
  secureSocksDSProxyEnabled: boolean;
};

export const HttpSettings = (props: Props) => {
  const { options, onOptionsChange, secureSocksDSProxyEnabled } = props;

  const newAuthProps = convertLegacyAuthProps({
    config: options,
    onChange: onOptionsChange,
  });

  const theme = useTheme2();
  const styles = overhaulStyles(theme);

  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  const jsonData = options.jsonData as PromOptionsWithGoogleAuth;
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  const secureJsonData = (options.secureJsonData ?? {}) as PromSecureJsonData;
  const secureJsonFields = options.secureJsonFields ?? {};
  const googleAuthType: GoogleAuthTypeValue = jsonData.googleAuthType ?? GoogleAuthType.None;
  const googleAuthEnabled = googleAuthType !== GoogleAuthType.None;
  const conflicts = collectGoogleAuthConflicts(options, jsonData);

  const onGoogleAuthTypeChange = (selected: SelectableValue<GoogleAuthTypeValue> | null) => {
    const next: GoogleAuthTypeValue = selected?.value ?? GoogleAuthType.None;
    onOptionsChange({
      ...options,
      // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
      jsonData: { ...options.jsonData, googleAuthType: next } as PromOptions,
    });
  };

  const onServiceAccountJsonChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
    onOptionsChange({
      ...options,
      secureJsonData: { ...(options.secureJsonData ?? {}), googleServiceAccountJson: event.currentTarget.value },
    });
  };

  const onServiceAccountJsonReset = () => {
    onOptionsChange({
      ...options,
      secureJsonFields: { ...secureJsonFields, googleServiceAccountJson: false },
      secureJsonData: { ...(options.secureJsonData ?? {}), googleServiceAccountJson: '' },
    });
  };

  // Do we need this switch anymore? Update the language.
  let urlTooltip;
  switch (options.access) {
    case 'direct':
      urlTooltip = (
        <>
          Your access method is <em>Browser</em>, this means the URL needs to be accessible from the browser.
          {docsTip()}
        </>
      );
      break;
    case 'proxy':
      urlTooltip = (
        <>
          Your access method is <em>Server</em>, this means the URL needs to be accessible from the grafana
          backend/server.
          {docsTip()}
        </>
      );
      break;
    default:
      urlTooltip = <>Specify a complete HTTP URL (for example http://your_server:8080) {docsTip()}</>;
  }

  return (
    <>
      <ConnectionSettings
        urlPlaceholder="http://localhost:9090"
        config={options}
        onChange={onOptionsChange}
        urlLabel="Prometheus server URL"
        urlTooltip={urlTooltip}
      />
      <hr className={`${styles.hrTopSpace} ${styles.hrBottomSpace}`} />
      <Auth
        {...newAuthProps}
        onAuthMethodSelect={(method) => {
          onOptionsChange({
            ...options,
            basicAuth: method === AuthMethod.BasicAuth,
            withCredentials: method === AuthMethod.CrossSiteCredentials,
            jsonData: {
              ...options.jsonData,
              oauthPassThru: method === AuthMethod.OAuthForward,
            },
          });
        }}
        // If your method is selected pass its id to `selectedMethod`,
        // otherwise pass the id from converted legacy data
        selectedMethod={newAuthProps.selectedMethod}
      />
      <div className={styles.sectionBottomPadding} />

      <ConfigSection title="Google Cloud authentication">
        <Stack direction="column" gap={2}>
          <Field label="Authentication type" noMargin>
            <Select
              aria-label="Google Cloud authentication"
              inputId="prometheus-google-auth-type"
              width={40}
              options={googleAuthOptions}
              value={googleAuthOptions.find((o) => o.value === googleAuthType) ?? googleAuthOptions[0]}
              onChange={onGoogleAuthTypeChange}
            />
          </Field>

          {googleAuthEnabled && conflicts.length > 0 && (
            <Alert severity="warning" title="Conflicting authentication">
              Google Cloud authentication will override {conflicts.join(', ')} for outgoing requests.
            </Alert>
          )}

          {googleAuthType === GoogleAuthType.ServiceAccountJSON && (
            <Field
              noMargin
              label="Service Account JSON key"
              description="Paste the contents of a Google Cloud service account JSON key. The value is encrypted at rest."
            >
              <SecretTextArea
                aria-label="Google Cloud service account JSON"
                id="prometheus-google-service-account-json"
                placeholder='{"type":"service_account", ...}'
                cols={45}
                rows={7}
                isConfigured={secureJsonFields.googleServiceAccountJson === true}
                value={secureJsonData.googleServiceAccountJson ?? ''}
                onChange={onServiceAccountJsonChange}
                onReset={onServiceAccountJsonReset}
              />
            </Field>
          )}
        </Stack>
      </ConfigSection>

      <div className={styles.sectionBottomPadding} />
      {secureSocksDSProxyEnabled && (
        <>
          <SecureSocksProxySettings options={options} onOptionsChange={onOptionsChange} />
          <div className={styles.sectionBottomPadding} />
        </>
      )}
    </>
  );
};

// Returns the human-readable names of auth modes configured in the Auth
// picker above that conflict with Google Cloud authentication. Limited to
// flags rendered in the same panel so the warning points at something the
// user can actually see and change.
function collectGoogleAuthConflicts(
  options: DataSourceSettings<PromOptions>,
  jsonData: PromOptionsWithGoogleAuth & { oauthPassThru?: boolean }
): string[] {
  const conflicts: string[] = [];
  if (options.basicAuth) {
    conflicts.push('Basic auth');
  }
  if (jsonData.oauthPassThru) {
    conflicts.push('Forward OAuth Identity');
  }
  return conflicts;
}
