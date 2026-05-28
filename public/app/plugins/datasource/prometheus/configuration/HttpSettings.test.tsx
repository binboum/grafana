import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { select } from 'react-select-event';

import { type DataSourceSettings } from '@grafana/data';
import { type PromOptions } from '@grafana/prometheus';

import { HttpSettings } from './HttpSettings';

// Replace Auth with a test double that exposes onAuthMethodSelect as buttons,
// so we can test the callback logic without depending on the Auth component's internal UI.
jest.mock('@grafana/plugin-ui', () => ({
  ...jest.requireActual('@grafana/plugin-ui'),
  Auth: ({ onAuthMethodSelect }: { onAuthMethodSelect: (method: string) => void }) => (
    <div>
      <button onClick={() => onAuthMethodSelect('BasicAuth')}>Basic auth</button>
      <button onClick={() => onAuthMethodSelect('OAuthForward')}>Forward OAuth Identity</button>
      <button onClick={() => onAuthMethodSelect('CrossSiteCredentials')}>Cross-site credentials</button>
    </div>
  ),
}));

function createDefaultConfigOptions(): DataSourceSettings<PromOptions> {
  return {
    jsonData: {},
    secureJsonData: {},
    secureJsonFields: {},
    access: 'proxy',
    basicAuth: false,
    withCredentials: false,
  } as DataSourceSettings<PromOptions>;
}

function renderWithGoogleAuth(overrides: Partial<DataSourceSettings<PromOptions>> = {}) {
  const onOptionsChange = jest.fn();
  const options = { ...createDefaultConfigOptions(), ...overrides } as DataSourceSettings<PromOptions>;
  render(<HttpSettings options={options} onOptionsChange={onOptionsChange} secureSocksDSProxyEnabled={false} />);
  return { onOptionsChange };
}

describe('HttpSettings', () => {
  it('renders without error', () => {
    expect(() =>
      render(
        <HttpSettings
          options={createDefaultConfigOptions()}
          onOptionsChange={() => {}}
          secureSocksDSProxyEnabled={false}
        />
      )
    ).not.toThrow();
  });

  it('renders the Prometheus server URL input', () => {
    render(
      <HttpSettings
        options={createDefaultConfigOptions()}
        onOptionsChange={() => {}}
        secureSocksDSProxyEnabled={false}
      />
    );
    expect(screen.getByPlaceholderText('http://localhost:9090')).toBeInTheDocument();
  });

  it('shows SecureSocksProxy settings when enabled', () => {
    render(
      <HttpSettings
        options={createDefaultConfigOptions()}
        onOptionsChange={() => {}}
        secureSocksDSProxyEnabled={true}
      />
    );
    expect(screen.getByText('Secure Socks Proxy')).toBeInTheDocument();
  });

  it('hides SecureSocksProxy settings when disabled', () => {
    render(
      <HttpSettings
        options={createDefaultConfigOptions()}
        onOptionsChange={() => {}}
        secureSocksDSProxyEnabled={false}
      />
    );
    expect(screen.queryByText('Secure Socks Proxy')).not.toBeInTheDocument();
  });

  it('calls onOptionsChange with basicAuth:true when BasicAuth is selected', async () => {
    const onOptionsChange = jest.fn();
    render(
      <HttpSettings
        options={createDefaultConfigOptions()}
        onOptionsChange={onOptionsChange}
        secureSocksDSProxyEnabled={false}
      />
    );
    await userEvent.click(screen.getByRole('button', { name: 'Basic auth' }));
    expect(onOptionsChange).toHaveBeenCalledWith(expect.objectContaining({ basicAuth: true, withCredentials: false }));
  });

  it('calls onOptionsChange with oauthPassThru:true when OAuthForward is selected', async () => {
    const onOptionsChange = jest.fn();
    render(
      <HttpSettings
        options={createDefaultConfigOptions()}
        onOptionsChange={onOptionsChange}
        secureSocksDSProxyEnabled={false}
      />
    );
    await userEvent.click(screen.getByRole('button', { name: 'Forward OAuth Identity' }));
    expect(onOptionsChange).toHaveBeenCalledWith(
      expect.objectContaining({
        basicAuth: false,
        withCredentials: false,
        jsonData: expect.objectContaining({ oauthPassThru: true }),
      })
    );
  });

  it('calls onOptionsChange with withCredentials:true when CrossSiteCredentials is selected', async () => {
    const onOptionsChange = jest.fn();
    render(
      <HttpSettings
        options={createDefaultConfigOptions()}
        onOptionsChange={onOptionsChange}
        secureSocksDSProxyEnabled={false}
      />
    );
    await userEvent.click(screen.getByRole('button', { name: 'Cross-site credentials' }));
    expect(onOptionsChange).toHaveBeenCalledWith(expect.objectContaining({ basicAuth: false, withCredentials: true }));
  });

  describe('Google Cloud authentication', () => {
    it('renders the Google Cloud authentication selector with "None" by default', () => {
      renderWithGoogleAuth();
      expect(screen.getByRole('heading', { name: 'Google Cloud authentication' })).toBeInTheDocument();
      expect(screen.getByText('None')).toBeInTheDocument();
      expect(screen.queryByLabelText('Google Cloud service account JSON')).not.toBeInTheDocument();
    });

    it('does not render the Service Account JSON field when ADC is selected', async () => {
      const { onOptionsChange } = renderWithGoogleAuth();
      await selectGoogleAuthOption('Google Cloud ADC');
      expect(onOptionsChange).toHaveBeenLastCalledWith(
        expect.objectContaining({ jsonData: expect.objectContaining({ googleAuthType: 'adc' }) })
      );
      expect(screen.queryByLabelText('Google Cloud service account JSON')).not.toBeInTheDocument();
    });

    it('reveals the Service Account JSON textarea when serviceAccountJson is selected', async () => {
      renderWithGoogleAuth({
        jsonData: { googleAuthType: 'serviceAccountJson' } as PromOptions,
      });
      expect(screen.getByLabelText('Google Cloud service account JSON')).toBeInTheDocument();
    });

    it('persists serviceAccountJson selection', async () => {
      const { onOptionsChange } = renderWithGoogleAuth();
      await selectGoogleAuthOption('Service Account JSON');
      expect(onOptionsChange).toHaveBeenLastCalledWith(
        expect.objectContaining({
          jsonData: expect.objectContaining({ googleAuthType: 'serviceAccountJson' }),
        })
      );
    });

    it('typing JSON updates secureJsonData.googleServiceAccountJson', async () => {
      const { onOptionsChange } = renderWithGoogleAuth({
        jsonData: { googleAuthType: 'serviceAccountJson' } as PromOptions,
      });
      const textarea = screen.getByLabelText('Google Cloud service account JSON');
      // user-event treats `{` as a key-descriptor delimiter; double it to type a literal `{`.
      await userEvent.type(textarea, '{{');
      expect(onOptionsChange).toHaveBeenCalledWith(
        expect.objectContaining({
          secureJsonData: expect.objectContaining({ googleServiceAccountJson: '{' }),
        })
      );
    });

    it('shows a Configured state and Reset button when the secret is set', async () => {
      renderWithGoogleAuth({
        jsonData: { googleAuthType: 'serviceAccountJson' } as PromOptions,
        secureJsonFields: { googleServiceAccountJson: true },
      });
      expect(screen.getByRole('button', { name: /reset/i })).toBeInTheDocument();
    });

    it('Reset clears the secure field and secureJsonFields flag', async () => {
      const { onOptionsChange } = renderWithGoogleAuth({
        jsonData: { googleAuthType: 'serviceAccountJson' } as PromOptions,
        secureJsonFields: { googleServiceAccountJson: true },
      });
      await userEvent.click(screen.getByRole('button', { name: /reset/i }));
      expect(onOptionsChange).toHaveBeenLastCalledWith(
        expect.objectContaining({
          secureJsonFields: expect.objectContaining({ googleServiceAccountJson: false }),
          secureJsonData: expect.objectContaining({ googleServiceAccountJson: '' }),
        })
      );
    });

    it('shows a conflict warning when basic auth is also enabled', () => {
      renderWithGoogleAuth({
        basicAuth: true,
        jsonData: { googleAuthType: 'adc' } as PromOptions,
      });
      expect(
        screen.getByText(/Google Cloud authentication will override.*Basic auth/i)
      ).toBeInTheDocument();
    });

    it('shows a conflict warning when oauthPassThru is also enabled', () => {
      renderWithGoogleAuth({
        jsonData: { googleAuthType: 'adc', oauthPassThru: true } as PromOptions,
      });
      expect(
        screen.getByText(/Google Cloud authentication will override.*Forward OAuth Identity/i)
      ).toBeInTheDocument();
    });

    it('does not show a conflict warning when only Google Cloud auth is set', () => {
      renderWithGoogleAuth({
        jsonData: { googleAuthType: 'adc' } as PromOptions,
      });
      expect(screen.queryByText(/Google Cloud authentication will override/i)).not.toBeInTheDocument();
    });

    it('does not show a conflict warning when Google Cloud auth is disabled, even if other modes are set', () => {
      renderWithGoogleAuth({
        basicAuth: true,
        jsonData: { oauthPassThru: true } as PromOptions,
      });
      expect(screen.queryByText(/Google Cloud authentication will override/i)).not.toBeInTheDocument();
    });
  });
});

async function selectGoogleAuthOption(label: string) {
  const input = screen.getByLabelText('Google Cloud authentication');
  await waitFor(() => select(input, label, { container: document.body }));
}
