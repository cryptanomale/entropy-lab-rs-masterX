# CI Secrets Checklist

The following secrets must be configured in your GitHub Repository settings (**Settings** > **Secrets and variables** > **Actions**).

## Required Secrets

| Secret Name | Description | Required For |
| :--- | :--- | :--- |
| `GITHUB_TOKEN` | Automatically provided by GitHub | `audit-check` |

## Optional Secrets (Future Use)

| Secret Name | Description | Required For |
| :--- | :--- | :--- |
| `SLACK_WEBHOOK` | Webhook URL for Slack notifications | Not currently enabled |
| `CRATES_TOKEN` | API token for publishing to crates.io | Release workflow (future) |

## Best Practices
1.  **Never** commit secrets to the repository.
2.  Use **Environment Secrets** for production deployment credentials.
3.  Rotate keys periodically (at least annually).
