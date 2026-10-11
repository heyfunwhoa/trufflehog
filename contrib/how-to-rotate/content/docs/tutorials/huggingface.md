---
title: Hugging Face
---

*This tutorial provides step-by-step instructions on how to rotate a Hugging Face User Access Token.*

TruffleHog detects Hugging Face credentials that start with `hf_` (User Access Tokens) and the legacy `api_org_` prefix (deprecated organization API tokens).

---

## Generate a new Hugging Face User Access Token

### Step 1 - Navigate to the Access Tokens page

The Access Tokens page is located at https://huggingface.co/settings/tokens.

To navigate there manually, click your avatar in the top-right corner, then click `Settings`, then `Access Tokens` in the left-hand navbar.

![](/images/huggingface/1.png)

### Step 2 - Generate a new User Access Token

#### 2a. Click `New token`

Click the `New token` button on the Access Tokens page.

#### 2b. Name the token and select a role

Give the token a descriptive name (for example, the app or machine that will use it). Then choose a role:

- `fine-grained` — scoped to specific repositories, organizations, and permissions. Use this for production, CI, and anything shared. The create form may offer presets such as Read-Only, Inference, Write, CI/CD, or Full Access; pick a preset or Custom, then grant only the permissions you need.
- `read` — read access to repositories you can already read, including private repos you or your organizations own.
- `write` — read access plus write access to repositories you can write to (push models, edit model cards, create repos).

![](/images/huggingface/2.png)

Prefer a `fine-grained` token with the least privilege required. Classic `read` / `write` tokens inherit access from your account and organization membership and have a larger blast radius if leaked.

If you scope a fine-grained token to a Team or Enterprise organization that requires administrator approval, the token stays **Pending** until an admin approves it.

#### 2c. Generate and copy the token

Click `Generate a token`. Copy the value immediately and store it in a password manager or secrets vault. Hugging Face User Access Tokens start with `hf_` and are shown only once.

---

## Replace the Leaked Hugging Face User Access Token

Replace the leaked Hugging Face User Access Token with the new one in all impacted applications and services. Common locations include:

- Environment variables such as `HF_TOKEN` or `HUGGING_FACE_HUB_TOKEN`
- CI/CD secrets, Hugging Face Spaces secrets, and secret managers
- Local CLI login (`hf auth login` or `huggingface-cli login`)
- Application code that passes `token=` into `transformers`, `datasets`, or `huggingface_hub`

---

## Revoke the Leaked Hugging Face User Access Token

### Step 1 - Navigate to the Access Tokens page

The Access Tokens page is located at https://huggingface.co/settings/tokens.

![](/images/huggingface/1.png)

### Step 2 - Revoke the User Access Token

#### 2a. Open `Manage` on the leaked token

Identify the leaked token and click the `Manage` dropdown.

![](/images/huggingface/3.png)

#### 2b. Delete the leaked token

Click `Delete` to permanently revoke that token. It stops working immediately.

`Invalidate and refresh` also kills the current value and issues a replacement with the same name and permissions. Use that only when you can update every consumer at the same time. For a leak, create a **new** token first (so you can scope it down), replace it everywhere, then `Delete` the leaked one.

### Revoke a token found in the wild

If you found somebody else's Hugging Face token (or need to invalidate a leaked value without signing in as the owner), call Hugging Face's public revoke endpoint. No account access is required. Matching tokens are invalidated everywhere immediately, and the owner is emailed.

```bash
# LEAKED_HF_TOKEN should contain the raw token value to revoke
curl -X POST "https://huggingface.co/api/credentials/revoke" \
  -H "Content-Type: application/json" \
  -d "{\"credentials\": [\"${LEAKED_HF_TOKEN}\"]}"
```

You can pass several token values in the `credentials` array. The endpoint always returns `202 Accepted`, whether or not the tokens existed, so the response cannot be used to probe whether a token is valid.

### Legacy `api_org_` organization tokens

Organization API tokens (`api_org_...`) are deprecated. If TruffleHog found one, revoke it with the endpoint above (or delete it if it still appears in organization settings) and replace it with a User Access Token or, on Enterprise, a [service account](https://huggingface.co/docs/hub/enterprise-service-accounts) token.

---

## Best Practices

##### Use one token per usage
Create a separate token for each machine, notebook, or service so you can revoke one without breaking the others.

##### Prefer fine-grained tokens in production
Scope production tokens to specific repos and permissions. Team and Enterprise orgs can require fine-grained tokens; classic `read` / `write` tokens then get `403` against that organization's resources.

##### Do not store long-lived tokens in CI when you can avoid it
Use [Trusted Publishers](https://huggingface.co/docs/hub/trusted-publishers) so CI exchanges an OIDC identity for a short-lived Hub token each run.

##### Rotate service account tokens for automation
On Enterprise, issue tokens from organization-owned [service accounts](https://huggingface.co/docs/hub/enterprise-service-accounts) rather than a personal account, and rotate them from the service account page if they are exposed.

---

## Resources
- [Hugging Face User Access Tokens](https://huggingface.co/docs/hub/security-tokens)
- [Tokens Management (Team & Enterprise)](https://huggingface.co/docs/hub/enterprise-tokens-management)
- [Trusted Publishers](https://huggingface.co/docs/hub/trusted-publishers)
- [Service Accounts](https://huggingface.co/docs/hub/enterprise-service-accounts)
- [TruffleHog Hugging Face detector](https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors/huggingface)
