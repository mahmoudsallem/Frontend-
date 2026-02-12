# Frontend Application

Task management frontend application built with React and served by Nginx.

## Architecture

This frontend is served by **Nginx**, which also acts as a reverse proxy for API requests.

- **Frontend Static Files**: Root path `/`
- **Backend API**: Proxied through `/api` to the backend service

## Tech Stack

- React 18
- Node.js 18
- Nginx (Production)
- Docker

## Local Development

To run the application locally for development:

1. Ensure you have Node.js installed
2. Install dependencies: `npm install`
3. Start the development server: `npm start`

The development server is configured to proxy API requests to `http://localhost:5000` via the `proxy` setting in `package.json`.

## Production

The production image is built using a multi-stage Docker build:
1. **Build Stage**: Compiles the React application
2. **Runtime Stage**: Nginx serves the compiled files and handles API proxying

---

## CI/CD Pipeline

The CI/CD pipeline is triggered on push to `main` or `dev` branches. It includes comprehensive security scanning, testing, and automated deployment.

### Pipeline Stages

```
STAGE 1: Credential Scanning
    |
STAGE 2: Parallel Scans & Tests
    |
STAGE 3: Build Docker Image
    |
STAGE 4: Container Security & DAST
    |
STAGE 5: Push to ECR & Sign
    |
STAGE 6: Update Helm Chart
    |
STAGE 7: Summary & Slack Notification
```

### Stage Details

#### Stage 1: Credential Scanning
| Job | Tool | Description |
|-----|------|-------------|
| `gitleaks` | Gitleaks | Scans repository for hardcoded secrets and credentials |

#### Stage 2: Parallel Scans & Tests (runs in parallel)
| Job | Tool | Description |
|-----|------|-------------|
| `frontend-checks` | ESLint, Jest | Linting and unit tests |
| `sast-semgrep` | Semgrep | Static Application Security Testing |
| `snyk-code` | Snyk | Open source dependency & code scanning |
| `js-security-scan` | njsscan, npm audit | JavaScript-specific security scanning |

#### Stage 3: Build
| Job | Tool | Description |
|-----|------|-------------|
| `build` | Docker Buildx | Builds Docker image with caching |

#### Stage 4: Container Security & DAST (runs in parallel)
| Job | Tool | Description |
|-----|------|-------------|
| `security-scan` | Trivy | Container vulnerability scanning |
| `snyk-container` | Snyk | Container image scanning |
| `dast-zap` | OWASP ZAP | Dynamic Application Security Testing |

#### Stage 5: Push & Sign
| Job | Tool | Description |
|-----|------|-------------|
| `push-and-sign` | AWS ECR, Cosign | Push image to ECR and sign with Cosign |

#### Stage 6: Update Helm Chart
| Job | Description |
|-----|-------------|
| `update-helm` | Updates Helm chart values with new image tag in Hellm repository |

#### Stage 7: Summary
| Job | Tool | Description |
|-----|------|-------------|
| `summary` | Slack | Pipeline summary and Slack notification |

---

## Required Secrets

### Repository Secrets
| Secret | Description |
|--------|-------------|
| `SNYK_TOKEN` | Snyk API token for security scanning |
| `SLACK_WEBHOOK_URL` | Slack webhook URL for notifications |

### Environment: `ECR_REPOSITORY`
| Secret | Description |
|--------|-------------|
| `AWS_ROLE_ARN` | AWS IAM Role ARN for OIDC authentication |
| `AWS_REGION` | AWS region (e.g., `us-east-1`) |
| `ECR_REPOSITORY` | ECR repository name |

### Environment: `Frontend_Update`
| Secret | Description |
|--------|-------------|
| `FRONTEND_UPDATE` | GitHub PAT with repo scope for Helm repo access |

### Environment: `SLACK_WEBHOOK_URL`
| Secret | Description |
|--------|-------------|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |

---

## Pipeline Features

- **Concurrency Control**: Prevents duplicate pipeline runs on the same branch
- **Short SHA Tags**: Uses 7-character SHA for image tags (e.g., `frontend-abc1234`)
- **Artifact Caching**: Docker layer caching via GitHub Actions cache
- **Security Reports**: Uploads SARIF reports to GitHub Security tab
- **Slack Notifications**: Sends pipeline status to Slack channel

---

## Image Tagging Strategy

| Tag | Description |
|-----|-------------|
| `frontend-<short-sha>` | Unique tag per commit (e.g., `frontend-abc1234`) |
| `frontend-latest` | Latest build from any branch |

---

## Helm Chart Integration

The pipeline automatically updates the Helm chart in the `mahmoudsallem/Hellm` repository:
- **Branch**: `dev`
- **File**: `helm/Dev/frontend/values.yaml`
- **Updated Field**: `image.tag`

---

## Security Scanning Summary

| Scan Type | Tool | Stage |
|-----------|------|-------|
| Credential Scan | Gitleaks | 1 |
| SAST | Semgrep, Snyk Code | 2 |
| Dependency Scan | Snyk, npm audit | 2 |
| JS Security | njsscan | 2 |
| Container Scan | Trivy, Snyk | 4 |
| DAST | OWASP ZAP | 4 |
| Image Signing | Cosign | 5 |
