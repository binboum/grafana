---
aliases:
  - ../data-sources/prometheus/
  - ../features/datasources/prometheus/
description: Guide for authenticating with Google Managed Service for Prometheus in Grafana
keywords:
  - grafana
  - prometheus
  - guide
labels:
  products:
    - cloud
    - enterprise
    - oss
menuTitle: Authenticating with Google Cloud
title: Configure the Prometheus data source
weight: 200
---

# Connect to Google Managed Service for Prometheus

After creating a Prometheus data source for Google Managed Service for Prometheus (GMP):

1. In the data source configuration page, locate the **Google Cloud authentication** section.

2. Select your **Authentication type**:

   - **Google Cloud ADC** &mdash; Application Default Credentials. Uses the metadata server on GCE, GKE Workload Identity, and Cloud Run, or `GOOGLE_APPLICATION_CREDENTIALS` pointing at a service-account key file.
   - **Service Account JSON** &mdash; Authenticates with a Google Cloud service account JSON key. The key is stored encrypted at rest.

3. When using **Service Account JSON**, paste the contents of a service account JSON key in the **Service Account JSON key** field.

4. Set the **Prometheus server URL** to your GMP endpoint:

   ```
   https://monitoring.googleapis.com/v1/projects/<PROJECT_ID>/location/global/prometheus
   ```

   Replace `<PROJECT_ID>` with your Google Cloud project ID.

5. Click **Save & test** to verify the connection.

## Required permissions

The identity used by the data source must have the `roles/monitoring.viewer` IAM role, or a custom role that grants read access to monitoring data, on the target project.

## Example configuration

Application Default Credentials, recommended on GCE, GKE, and Cloud Run:

```yaml
apiVersion: 1
datasources:
  - name: GMP (ADC)
    type: prometheus
    access: proxy
    url: https://monitoring.googleapis.com/v1/projects/my-project/location/global/prometheus
    jsonData:
      httpMethod: POST
      googleAuthType: adc
```

Service account JSON key:

```yaml
apiVersion: 1
datasources:
  - name: GMP (Service Account)
    type: prometheus
    access: proxy
    url: https://monitoring.googleapis.com/v1/projects/my-project/location/global/prometheus
    jsonData:
      httpMethod: POST
      googleAuthType: serviceAccountJson
    secureJsonData:
      googleServiceAccountJson: |
        {
          "type": "service_account",
          "project_id": "...",
          "private_key_id": "...",
          "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
          "client_email": "...@....iam.gserviceaccount.com",
          "client_id": "...",
          "token_uri": "https://oauth2.googleapis.com/token"
        }
```

{{< admonition type="note" >}}
Google Cloud authentication overrides any `Authorization` header produced by Basic auth, Forward OAuth Identity, or a custom HTTP header on the same data source. The data source UI displays a warning when these settings are configured together.
{{< /admonition >}}
