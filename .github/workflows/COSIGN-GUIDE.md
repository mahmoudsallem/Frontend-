# Cosign Image Signing Guide

## Overview
The CI/CD pipeline now includes **Cosign keyless signing** to cryptographically sign Docker images, providing supply chain security and image verification.

## What is Cosign?

**Cosign** is a tool from the Sigstore project that signs and verifies container images. It provides:
- ✅ Cryptographic proof of image authenticity
- ✅ Verification of image integrity
- ✅ Supply chain security
- ✅ Keyless signing using OIDC (no key management needed)

## How It Works

### Keyless Signing (OIDC)
Instead of managing cryptographic keys, Cosign uses **OpenID Connect (OIDC)** authentication:

1. GitHub Actions provides an OIDC token (identity proof)
2. Cosign uses this token to sign the image
3. The signature is stored in a transparency log (Rekor)
4. Anyone can verify the signature using the public transparency log

### Image Digest
- Images are signed using their **SHA256 digest**
- Digest is immutable (unlike tags which can change)
- Ensures you're verifying the exact image that was signed

## Pipeline Integration

### Job: `cosign-sign`

**Location**: Runs after `dockerfile-check` job

**Permissions Required**:
```yaml
permissions:
  contents: read
  id-token: write  # Required for OIDC keyless signing
```

**Steps**:

1. **Install Cosign** - Uses official Sigstore installer
2. **Build Docker Image** - Creates the image and captures digest
3. **Sign Image** - Signs using keyless mode with OIDC
4. **Verify Signature** - Immediately verifies the signature
5. **Generate Attestation** - Logs signature information

## Verification

### In the Pipeline
The signature is automatically verified after signing:

```bash
cosign verify backend-app:${{ github.sha }} \
  --certificate-identity-regexp="https://github.com/${{ github.repository }}/*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### Manual Verification
Anyone can verify your signed images:

```bash
# Install Cosign
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# Verify the image (replace with your image details)
COSIGN_EXPERIMENTAL=1 cosign verify backend-app:IMAGE_TAG \
  --certificate-identity-regexp="https://github.com/YOUR_REPO/*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

## Signature Information

Each signed image includes:
- **Repository**: GitHub repository that signed it
- **Commit SHA**: Exact commit that triggered the signing
- **Image Tag**: The tagged version
- **Image Digest**: SHA256 digest of the image
- **Workflow**: GitHub Actions workflow name
- **Run ID**: Specific workflow run

## Security Benefits

### 1. **Authenticity**
Proves the image was built by your GitHub Actions workflow

### 2. **Integrity**
Ensures the image hasn't been tampered with since signing

### 3. **Non-Repudiation**
Signature is logged in public transparency log (Rekor)

### 4. **Supply Chain Security**
Part of the SLSA (Supply-chain Levels for Software Artifacts) framework

## Transparency Log

All signatures are recorded in **Rekor** (public transparency log):
- View at: https://search.sigstore.dev/
- Search by image digest or repository
- Provides audit trail

## Configuration Options

### Change Signing Behavior

**Sign only on specific branches**:
```yaml
cosign-sign:
  if: github.ref == 'refs/heads/main'
```

**Sign with additional metadata**:
```yaml
- name: Sign with annotations
  run: |
    cosign sign --yes \
      -a "commit=${{ github.sha }}" \
      -a "repo=${{ github.repository }}" \
      ${{ steps.build.outputs.image_tag }}
```

### Verify in Deployment

Add verification before deploying:
```yaml
- name: Verify before deploy
  env:
    COSIGN_EXPERIMENTAL: "true"
  run: |
    cosign verify $IMAGE_NAME \
      --certificate-identity-regexp="https://github.com/${{ github.repository }}/*" \
      --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

## Troubleshooting

### Error: "signing [backend-app:xxx]: getting signer: getting key from Fulcio"
- **Cause**: OIDC token issue
- **Solution**: Ensure `id-token: write` permission is set

### Error: "no signatures found"
- **Cause**: Image not signed or wrong image reference
- **Solution**: Check image tag/digest matches signed image

### Error: "certificate identity mismatch"
- **Cause**: Verification identity doesn't match signer
- **Solution**: Update `--certificate-identity-regexp` to match your repo

## Best Practices

1. ✅ **Always verify signatures** before deploying to production
2. ✅ **Use image digests** instead of tags for deployment
3. ✅ **Monitor Rekor logs** for unauthorized signatures
4. ✅ **Integrate with admission controllers** (e.g., Kyverno, OPA)
5. ✅ **Document signing policies** in your security guidelines

## Integration with Container Registries

### Docker Hub
```bash
# Sign after pushing
docker push myrepo/backend-app:latest
cosign sign --yes myrepo/backend-app:latest
```

### GitHub Container Registry (GHCR)
```yaml
- name: Login to GHCR
  uses: docker/login-action@v2
  with:
    registry: ghcr.io
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}

- name: Push and sign
  run: |
    docker tag backend-app:${{ github.sha }} ghcr.io/${{ github.repository }}:latest
    docker push ghcr.io/${{ github.repository }}:latest
    cosign sign --yes ghcr.io/${{ github.repository }}:latest
```

## Kubernetes Integration

### Verify Images in Kubernetes

Use **Kyverno** policy:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-cosign-signature
spec:
  validationFailureAction: enforce
  rules:
  - name: verify-signature
    match:
      resources:
        kinds:
        - Pod
    verifyImages:
    - imageReferences:
      - "ghcr.io/your-repo/*"
      attestors:
      - entries:
        - keyless:
            subject: "https://github.com/your-repo/*"
            issuer: "https://token.actions.githubusercontent.com"
```

## Next Steps

1. ✅ Push the updated workflow to GitHub
2. ✅ Check the Actions tab for successful signing
3. ✅ Verify signatures manually using Cosign CLI
4. ✅ Integrate signature verification in deployment pipelines
5. ✅ Consider adding SBOM (Software Bill of Materials) generation

## Additional Resources

- **Sigstore**: https://www.sigstore.dev/
- **Cosign Documentation**: https://docs.sigstore.dev/cosign/overview/
- **Rekor Transparency Log**: https://search.sigstore.dev/
- **SLSA Framework**: https://slsa.dev/
