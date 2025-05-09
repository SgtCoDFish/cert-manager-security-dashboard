# cert-manager-security-dashboard

This is a really simple dashboard application for fetching security data from the GitHub API for the various repos in the cert-manager organisation.

The dashboard is packaged as a single Go binary. The only configuration required is a GitHub API token, provided through the `GITHUB_TOKEN` environment variable.
