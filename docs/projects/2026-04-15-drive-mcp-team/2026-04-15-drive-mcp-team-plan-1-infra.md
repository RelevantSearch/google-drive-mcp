---
version: 1
---

# Drive MCP — Plan 1: Infrastructure (rs_infra)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Steps use `- [ ]` syntax for tracking.

**Parent:** [index.md](./index.md) | **Design:** [design doc](./2026-04-15-drive-mcp-team-design.md)

**Goal:** Provision Cloud Run + Firestore + KMS + LB + DNS + Secret Manager in `rs-workspace-integrations` (nonprod) to host the Drive MCP server.

**Architecture:** New reusable Terragrunt module `modules/workspace-integrations-mcp/`, instantiated from `environments/non-production/workspace-integrations/drive-mcp/`. All CMEK via dedicated KMS keys in `kms-proj-a9dncstlc3zg`. First apply is manual (bootstraps KMS), subsequent via CI.

**Tech Stack:** OpenTofu, Terragrunt, GCP (Cloud Run, Firestore, KMS, Cloud Load Balancer, Certificate Manager, Cloud DNS, Artifact Registry, Secret Manager, IAM), SOPS.

**Worktree:** `~/git/RS/rs_infra_feat-drive-mcp-team/` on branch `feat/drive-mcp-team`.

**Reference module:** `modules/firebase-hosting/` — use as template for CMEK patterns, serverless NEG, LB, cert manager, depends_on bindings. Do not fork it; write a smaller, purpose-built module.

---

## File structure

**New files:**

```
modules/workspace-integrations-mcp/
├── README.md                  # module usage docs
├── versions.tf                # provider pins
├── variables.tf               # module inputs
├── outputs.tf                 # LB IP, SA email, Cloud Run URL, Firestore DB id
├── main.tf                    # Cloud Run + Artifact Registry + service account + IAM
├── kms.tf                     # keyring + 4 crypto keys + service identity CMEK bindings
├── firestore.tf               # Firestore DB with CMEK + service identity binding
├── secrets.tf                 # SOPS decrypt + Secret Manager resources
├── lb.tf                      # serverless NEG + backend + URL map + HTTPS proxy + cert
├── dns.tf                     # A record for custom domain → LB IP
└── tests/
    └── drive_mcp_module_test.tftest.hcl

environments/non-production/workspace-integrations/
└── drive-mcp/
    └── terragrunt.hcl

secrets/
└── workspace-integrations.enc.yaml  # SOPS, populated in Task 14
```

**No files modified** outside the new module + env + secret file.

---

### Task 1: Module skeleton + versions.tf

**Files:**
- Create: `modules/workspace-integrations-mcp/versions.tf`
- Create: `modules/workspace-integrations-mcp/variables.tf`
- Create: `modules/workspace-integrations-mcp/outputs.tf`
- Create: `modules/workspace-integrations-mcp/main.tf` (empty stub)
- Create: `modules/workspace-integrations-mcp/README.md`

- [ ] **Step 1: Create versions.tf**

```hcl
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.0"
    }
    sops = {
      source  = "carlpett/sops"
      version = "~> 1.1"
    }
  }
}
```

- [ ] **Step 2: Create variables.tf with module inputs**

```hcl
variable "project_id" {
  description = "Workspace integrations project (e.g. rs-workspace-integrations)"
  type        = string
}

variable "project_number" {
  description = "GCP project number (required for service identity lookups)"
  type        = string
}

variable "region" {
  description = "GCP region for Cloud Run, Firestore, Artifact Registry"
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Cloud Run service name (also used as resource name prefix)"
  type        = string
  default     = "drive-mcp"
}

variable "custom_domain" {
  description = "FQDN for the MCP server (e.g. drive-mcp.relevantsearch.com)"
  type        = string
}

variable "dns_zone_name" {
  description = "Existing Cloud DNS managed zone name (e.g. relevant-search-main)"
  type        = string
}

variable "dns_zone_project" {
  description = "Project hosting the DNS zone"
  type        = string
}

variable "kms_project_id" {
  description = "Project hosting KMS keys (e.g. kms-proj-a9dncstlc3zg for nonprod)"
  type        = string
}

variable "kms_keyring_name" {
  description = "Keyring name (created by this module if not existing)"
  type        = string
  default     = "drive-mcp"
}

variable "sops_secrets_file" {
  description = "Path to the SOPS-encrypted secrets file for this env"
  type        = string
}

variable "image" {
  description = "Full container image URI (e.g. us-central1-docker.pkg.dev/.../drive-mcp:sha)"
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "min_instances" {
  type    = number
  default = 1
}

variable "max_instances" {
  type    = number
  default = 10
}
```

- [ ] **Step 3: Create outputs.tf**

```hcl
output "service_account_email" {
  value = google_service_account.drive_mcp.email
}

output "cloud_run_url" {
  value = google_cloud_run_v2_service.drive_mcp.uri
}

output "firestore_database_id" {
  value = google_firestore_database.drive_mcp.name
}

output "lb_ip_address" {
  value = google_compute_global_address.drive_mcp.address
}

output "artifact_registry_repo" {
  value = "${google_artifact_registry_repository.drive_mcp.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.drive_mcp.repository_id}"
}
```

- [ ] **Step 4: Create stub main.tf**

```hcl
# Drive MCP workspace integration module.
# Populated across tasks 2-10 of plan-1-infra.
```

- [ ] **Step 5: Create README.md stub**

```markdown
# workspace-integrations-mcp

Terragrunt module for the Drive MCP Cloud Run service. See
`docs/projects/2026-04-15-drive-mcp-team/` for design and rollout context.
```

- [ ] **Step 6: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): scaffold module skeleton"
```

---

### Task 2: KMS keyring + 4 crypto keys

**Files:**
- Create: `modules/workspace-integrations-mcp/kms.tf`

- [ ] **Step 1: Write the failing test**

Create `modules/workspace-integrations-mcp/tests/drive_mcp_module_test.tftest.hcl`:

```hcl
# Minimal validation tests. Extend as tasks progress.
variables {
  project_id       = "test-proj"
  project_number   = "000000000000"
  custom_domain    = "drive-mcp.example.com"
  dns_zone_name    = "test-zone"
  dns_zone_project = "test-dns-proj"
  kms_project_id   = "test-kms-proj"
  sops_secrets_file = "/tmp/does-not-exist.enc.yaml"
}

run "kms_keys_created" {
  command = plan

  assert {
    condition     = length([for k in keys(google_kms_crypto_key.key) : k]) == 4
    error_message = "Expected 4 crypto keys (cloud_run, firestore, secrets, token)"
  }
}
```

- [ ] **Step 2: Run test — expect fail (`google_kms_crypto_key.key` undefined)**

```bash
cd ~/git/RS/rs_infra_feat-drive-mcp-team/modules/workspace-integrations-mcp
tofu init
tofu test
```

Expected: FAIL with "resource not declared".

- [ ] **Step 3: Create kms.tf**

```hcl
locals {
  kms_keys = {
    cloud_run = { rotation_period_seconds = 7776000 }  # 90 days
    firestore = { rotation_period_seconds = 7776000 }
    secrets   = { rotation_period_seconds = 7776000 }
    token     = { rotation_period_seconds = 7776000 }  # app-level envelope encryption
  }
}

resource "google_kms_key_ring" "drive_mcp" {
  project  = var.kms_project_id
  name     = var.kms_keyring_name
  location = var.region
}

resource "google_kms_crypto_key" "key" {
  for_each        = local.kms_keys
  name            = "${var.service_name}-${each.key}"
  key_ring        = google_kms_key_ring.drive_mcp.id
  rotation_period = "${each.value.rotation_period_seconds}s"
  purpose         = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }
}
```

- [ ] **Step 4: Re-run test — expect pass**

```bash
tofu test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): add KMS keyring and 4 crypto keys"
```

---

### Task 3: Service identity IAM bindings (CMEK consumers)

**Files:**
- Modify: `modules/workspace-integrations-mcp/kms.tf`

- [ ] **Step 1: Append service identity bindings to kms.tf**

Each GCP service that needs to *consume* CMEK must have its own service identity granted `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the specific key. Based on lessons from PR #89: **use `google_project_service_identity` (beta) to force identity creation**, then use `google_kms_crypto_key_iam_member` with explicit `depends_on`.

```hcl
# Firestore service identity
resource "google_project_service_identity" "firestore" {
  provider = google-beta
  project  = var.project_id
  service  = "firestore.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "firestore_sa" {
  crypto_key_id = google_kms_crypto_key.key["firestore"].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.firestore.email}"
}

# Cloud Run service identity (uses per-project service agent)
data "google_project" "current" {
  project_id = var.project_id
}

resource "google_kms_crypto_key_iam_member" "cloud_run_sa" {
  crypto_key_id = google_kms_crypto_key.key["cloud_run"].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@serverless-robot-prod.iam.gserviceaccount.com"
}

# Secret Manager service identity
resource "google_project_service_identity" "secretmanager" {
  provider = google-beta
  project  = var.project_id
  service  = "secretmanager.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "secretmanager_sa" {
  crypto_key_id = google_kms_crypto_key.key["secrets"].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.secretmanager.email}"
}
```

Note: the `token` key is consumed by the app's own service account (Task 4 creates it); binding added in Task 4.

- [ ] **Step 2: Re-run `tofu validate` and `tofu test`**

```bash
cd ~/git/RS/rs_infra_feat-drive-mcp-team/modules/workspace-integrations-mcp
tofu validate
tofu test
```

Expected: validate and test both PASS.

- [ ] **Step 3: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/kms.tf
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): add CMEK service identity bindings"
```

---

### Task 4: App service account + token key binding

**Files:**
- Create: `modules/workspace-integrations-mcp/iam.tf`

- [ ] **Step 1: Create iam.tf**

```hcl
resource "google_service_account" "drive_mcp" {
  project      = var.project_id
  account_id   = var.service_name
  display_name = "Drive MCP Cloud Run service account"
}

resource "google_project_iam_member" "drive_mcp_datastore" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.drive_mcp.email}"
}

resource "google_project_iam_member" "drive_mcp_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.drive_mcp.email}"
}

# Token envelope key: encrypt+decrypt for this SA only.
resource "google_kms_crypto_key_iam_member" "drive_mcp_token_key" {
  crypto_key_id = google_kms_crypto_key.key["token"].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.drive_mcp.email}"
}

# Secret Manager secret accessor (specific secrets bound in secrets.tf)
```

- [ ] **Step 2: Validate and test**

```bash
cd ~/git/RS/rs_infra_feat-drive-mcp-team/modules/workspace-integrations-mcp
tofu validate
tofu test
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/iam.tf
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): add app service account and token key binding"
```

---

### Task 5: Firestore database with CMEK

**Files:**
- Create: `modules/workspace-integrations-mcp/firestore.tf`

- [ ] **Step 1: Create firestore.tf**

Known gotcha (PR #89): IAM binding on the KMS key is eventually consistent. Without `depends_on`, Firestore apply fails with a transient permission error. We pin the dependency explicitly.

```hcl
resource "google_firestore_database" "drive_mcp" {
  project                     = var.project_id
  name                        = "(default)"
  location_id                 = var.region
  type                        = "FIRESTORE_NATIVE"
  concurrency_mode            = "OPTIMISTIC"
  app_engine_integration_mode = "DISABLED"
  deletion_policy             = "DELETE_PROTECTION_ENABLED"

  cmek_config {
    kms_key_name = google_kms_crypto_key.key["firestore"].id
  }

  depends_on = [
    google_kms_crypto_key_iam_member.firestore_sa,
  ]
}
```

- [ ] **Step 2: Add a test assertion**

Append to `tests/drive_mcp_module_test.tftest.hcl`:

```hcl
run "firestore_cmek_configured" {
  command = plan

  assert {
    condition     = google_firestore_database.drive_mcp.cmek_config[0].kms_key_name != ""
    error_message = "Firestore CMEK key_name must be set"
  }
}
```

- [ ] **Step 3: Validate and test**

```bash
tofu test
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): add Firestore with CMEK"
```

---

### Task 6: Artifact Registry repo (CMEK)

**Files:**
- Modify: `modules/workspace-integrations-mcp/main.tf`

- [ ] **Step 1: Append to main.tf**

```hcl
resource "google_artifact_registry_repository" "drive_mcp" {
  project       = var.project_id
  location      = var.region
  repository_id = var.service_name
  format        = "DOCKER"
  description   = "Drive MCP container images"

  kms_key_name = google_kms_crypto_key.key["cloud_run"].id

  depends_on = [
    google_kms_crypto_key_iam_member.cloud_run_sa,
  ]
}
```

- [ ] **Step 2: Validate + test**

```bash
tofu validate
tofu test
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/main.tf
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): add Artifact Registry with CMEK"
```

---

### Task 7: SOPS + Secret Manager resources

**Files:**
- Create: `modules/workspace-integrations-mcp/secrets.tf`

Secrets to provision (SOPS-encrypted values pulled at plan time, not logged):
- `drive-mcp-google-oauth-client-id`
- `drive-mcp-google-oauth-client-secret`
- `drive-mcp-mcp-signing-key`

The SOPS file is populated in Task 14 (after Google OAuth client is created manually). For now, the resources are defined but values come from a `for_each` over the decrypted map.

- [ ] **Step 1: Create secrets.tf**

```hcl
data "sops_file" "secrets" {
  source_file = var.sops_secrets_file
}

locals {
  secret_names = [
    "drive-mcp-google-oauth-client-id",
    "drive-mcp-google-oauth-client-secret",
    "drive-mcp-mcp-signing-key",
  ]
}

resource "google_secret_manager_secret" "secret" {
  for_each  = toset(local.secret_names)
  project   = var.project_id
  secret_id = each.value

  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.key["secrets"].id
        }
      }
    }
  }

  depends_on = [
    google_kms_crypto_key_iam_member.secretmanager_sa,
  ]
}

resource "google_secret_manager_secret_version" "version" {
  for_each    = toset(local.secret_names)
  secret      = google_secret_manager_secret.secret[each.value].id
  secret_data = lookup(data.sops_file.secrets.data, each.value, "")

  lifecycle {
    ignore_changes = [secret_data]  # allow manual rotation without Terraform drift
  }
}

resource "google_secret_manager_secret_iam_member" "app_accessor" {
  for_each  = toset(local.secret_names)
  project   = var.project_id
  secret_id = google_secret_manager_secret.secret[each.value].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.drive_mcp.email}"
}
```

- [ ] **Step 2: Create placeholder SOPS file at repo root**

Create `secrets/workspace-integrations.enc.yaml` with empty placeholder values, then encrypt it. The actual values are populated in Task 14.

```bash
cd ~/git/RS/rs_infra_feat-drive-mcp-team
cat > /tmp/ws-secrets-plain.yaml <<'EOF'
drive-mcp-google-oauth-client-id: PLACEHOLDER_FILLED_IN_TASK_14
drive-mcp-google-oauth-client-secret: PLACEHOLDER_FILLED_IN_TASK_14
drive-mcp-mcp-signing-key: PLACEHOLDER_FILLED_IN_TASK_14
EOF
sops --encrypt /tmp/ws-secrets-plain.yaml > secrets/workspace-integrations.enc.yaml
rm /tmp/ws-secrets-plain.yaml
```

- [ ] **Step 3: Validate**

```bash
cd ~/git/RS/rs_infra_feat-drive-mcp-team/modules/workspace-integrations-mcp
tofu validate
```

Expected: PASS (test not run here — `tofu test` can't decrypt SOPS).

- [ ] **Step 4: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/secrets.tf secrets/workspace-integrations.enc.yaml
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): add Secret Manager secrets with SOPS source"
```

---

### Task 8: Cloud Run service

**Files:**
- Modify: `modules/workspace-integrations-mcp/main.tf`

Initial deploy uses Cloud Run's public hello-world image (`var.image` default). Real image comes from the app repo's CI in Plan 2.

- [ ] **Step 1: Append to main.tf**

```hcl
resource "google_cloud_run_v2_service" "drive_mcp" {
  project  = var.project_id
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.drive_mcp.email
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    containers {
      image = var.image

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        startup_cpu_boost = true
      }

      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "FIRESTORE_DATABASE"
        value = google_firestore_database.drive_mcp.name
      }
      env {
        name  = "KMS_TOKEN_KEY"
        value = google_kms_crypto_key.key["token"].id
      }
      env {
        name  = "PUBLIC_URL"
        value = "https://${var.custom_domain}"
      }
      env {
        name = "GOOGLE_OAUTH_CLIENT_ID"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.secret["drive-mcp-google-oauth-client-id"].secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "GOOGLE_OAUTH_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.secret["drive-mcp-google-oauth-client-secret"].secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "MCP_SIGNING_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.secret["drive-mcp-mcp-signing-key"].secret_id
            version = "latest"
          }
        }
      }
    }

    encryption_key = google_kms_crypto_key.key["cloud_run"].id
  }

  depends_on = [
    google_kms_crypto_key_iam_member.cloud_run_sa,
    google_firestore_database.drive_mcp,
  ]
}

# Public invoker — auth is handled by the MCP OAuth flow inside the app.
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = google_cloud_run_v2_service.drive_mcp.location
  name     = google_cloud_run_v2_service.drive_mcp.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
```

- [ ] **Step 2: Validate + test**

```bash
tofu validate
tofu test
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/main.tf
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): add Cloud Run service with CMEK"
```

---

### Task 9: Load balancer, serverless NEG, managed cert

**Files:**
- Create: `modules/workspace-integrations-mcp/lb.tf`

Known gotcha (success-dna #44): serverless NEG — not Internet NEG. Another gotcha (PR #90): cert manager CNAME must be created. We use `google_compute_managed_ssl_certificate` (simpler, no DNS auth needed) since the domain is a single host and we control the DNS zone.

- [ ] **Step 1: Create lb.tf**

```hcl
resource "google_compute_region_network_endpoint_group" "drive_mcp" {
  provider              = google-beta
  project               = var.project_id
  name                  = "${var.service_name}-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.drive_mcp.name
  }
}

resource "google_compute_backend_service" "drive_mcp" {
  project               = var.project_id
  name                  = "${var.service_name}-backend"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"

  backend {
    group = google_compute_region_network_endpoint_group.drive_mcp.id
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "drive_mcp" {
  project         = var.project_id
  name            = "${var.service_name}-urlmap"
  default_service = google_compute_backend_service.drive_mcp.id
}

resource "google_compute_managed_ssl_certificate" "drive_mcp" {
  project = var.project_id
  name    = "${var.service_name}-cert"

  managed {
    domains = [var.custom_domain]
  }
}

resource "google_compute_target_https_proxy" "drive_mcp" {
  project          = var.project_id
  name             = "${var.service_name}-https-proxy"
  url_map          = google_compute_url_map.drive_mcp.id
  ssl_certificates = [google_compute_managed_ssl_certificate.drive_mcp.id]
}

resource "google_compute_global_address" "drive_mcp" {
  project = var.project_id
  name    = "${var.service_name}-ip"
}

resource "google_compute_global_forwarding_rule" "drive_mcp" {
  project               = var.project_id
  name                  = "${var.service_name}-fr"
  target                = google_compute_target_https_proxy.drive_mcp.id
  port_range            = "443"
  ip_address            = google_compute_global_address.drive_mcp.address
  load_balancing_scheme = "EXTERNAL_MANAGED"
}
```

- [ ] **Step 2: Validate + test**

```bash
tofu validate
tofu test
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/lb.tf
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): add LB with serverless NEG and managed cert"
```

---

### Task 10: DNS A record

**Files:**
- Create: `modules/workspace-integrations-mcp/dns.tf`

Managed SSL cert provisioning is triggered by DNS resolving the domain to the LB IP, so we only need the A record — no CNAME for DNS auth.

- [ ] **Step 1: Create dns.tf**

```hcl
resource "google_dns_record_set" "drive_mcp_a" {
  project      = var.dns_zone_project
  managed_zone = var.dns_zone_name
  name         = "${var.custom_domain}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.drive_mcp.address]
}
```

- [ ] **Step 2: Validate + test**

```bash
tofu validate
tofu test
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/dns.tf
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations-mcp): add DNS A record for custom domain"
```

---

### Task 11: Terragrunt environment wiring

**Files:**
- Create: `environments/non-production/workspace-integrations/drive-mcp/terragrunt.hcl`

- [ ] **Step 1: Create terragrunt.hcl**

```hcl
# Drive MCP — Non-Production (rs-workspace-integrations)

include "root" {
  path = find_in_parent_folders("root.hcl")
}

include "env" {
  path   = "${get_terragrunt_dir()}/../../../_env/non-production.hcl"
  expose = true
}

terraform {
  source = "${get_terragrunt_dir()}/../../../../modules/workspace-integrations-mcp"
}

inputs = {
  project_id     = "rs-workspace-integrations"
  region         = "us-central1"

  service_name     = "drive-mcp"
  custom_domain    = "drive-mcp.relevantsearch.com"

  dns_zone_name    = "relevant-search-main"
  dns_zone_project = "rs-infra-484217"

  kms_project_id   = "kms-proj-a9dncstlc3zg"
  kms_keyring_name = "drive-mcp"

  sops_secrets_file = "${get_terragrunt_dir()}/../../../../secrets/workspace-integrations.enc.yaml"

  # First apply uses hello-world; real image comes from Plan 2 CI.
  image = "us-docker.pkg.dev/cloudrun/container/hello"

  min_instances = 1
  max_instances = 10
}
```

- [ ] **Step 2: Run `terragrunt init` and `terragrunt validate`**

```bash
cd ~/git/RS/rs_infra_feat-drive-mcp-team/environments/non-production/workspace-integrations/drive-mcp
terragrunt init
terragrunt validate
```

Expected: Both PASS.

- [ ] **Step 3: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add environments/non-production/workspace-integrations/
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "feat(workspace-integrations): wire drive-mcp nonprod env"
```

---

### Task 12: Populate outputs.tf and module README

**Files:**
- Modify: `modules/workspace-integrations-mcp/outputs.tf` (already created in Task 1 — verify)
- Modify: `modules/workspace-integrations-mcp/README.md`

- [ ] **Step 1: Expand README.md**

```markdown
# workspace-integrations-mcp

Terragrunt module that provisions the Drive MCP Cloud Run service with:

- Cloud Run v2 (CMEK, min=1, max=10, 512MB)
- Firestore Native with CMEK
- Cloud KMS keyring with 4 rotation-enabled keys
- Artifact Registry with CMEK
- Secret Manager (3 secrets via SOPS)
- External HTTPS load balancer (serverless NEG, managed SSL cert)
- Custom domain + DNS A record

## Usage

See `environments/non-production/workspace-integrations/drive-mcp/terragrunt.hcl`.

## Required inputs

| Input | Example |
|---|---|
| `project_id` | `rs-workspace-integrations` |
| `project_number` | `1091285608879` |
| `custom_domain` | `drive-mcp.relevantsearch.com` |
| `dns_zone_name` | `relevant-search-main` |
| `dns_zone_project` | `rs-infra-484217` |
| `kms_project_id` | `kms-proj-a9dncstlc3zg` (nonprod) |
| `sops_secrets_file` | path to encrypted YAML with OAuth client + signing key |

## Outputs

| Output | Purpose |
|---|---|
| `service_account_email` | For CI WIF impersonation |
| `cloud_run_url` | Used by the app repo during smoke tests |
| `lb_ip_address` | For DNS verification |
| `artifact_registry_repo` | Used by Plan 2 CI to push images |

## Bootstrapping

First apply is manual — it creates the KMS keyring + keys which CI does not
have permission to create. After first apply, CI handles updates via WIF.

See `docs/projects/2026-04-15-drive-mcp-team/` for design and rollout.
```

- [ ] **Step 2: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add modules/workspace-integrations-mcp/README.md
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "docs(workspace-integrations-mcp): expand README"
```

---

### Task 13: Manual Google OAuth client creation (one-time)

**Not a code task — a runbook step the operator (Stefan) executes before Task 14.**

- [ ] **Step 1: Enable required APIs in `rs-workspace-integrations`**

API enablement is now handled by the `workspace-integrations-mcp` module (see `apis.tf`). No manual step needed.

- [ ] **Step 2: Configure OAuth consent screen**

Cloud Console → APIs & Services → OAuth consent screen → Internal type.

- App name: `Relevant Search Drive MCP`
- User support email: `stefan@relevantsearch.com`
- Scopes: `.../auth/drive`, `.../auth/documents`, `.../auth/spreadsheets`, `.../auth/presentations`
- Authorized domain: `relevantsearch.com`

- [ ] **Step 3: Create OAuth 2.0 Client ID**

APIs & Services → Credentials → Create Credentials → OAuth client ID.

- Application type: Web application
- Name: `drive-mcp-server`
- Authorized redirect URI: `https://drive-mcp.relevantsearch.com/oauth/google/callback`

Copy the client ID and client secret — they go into SOPS in Task 14.

- [ ] **Step 4: Generate the MCP signing key**

```bash
openssl rand -base64 64
```

Copy output — this is the HMAC secret for our JWTs.

---

### Task 14: Populate SOPS secrets

**Files:**
- Modify: `secrets/workspace-integrations.enc.yaml`

- [ ] **Step 1: Decrypt, edit, re-encrypt**

```bash
cd ~/git/RS/rs_infra_feat-drive-mcp-team
sops secrets/workspace-integrations.enc.yaml
```

Replace the three placeholder values with the real ones from Task 13.

- [ ] **Step 2: Verify sops can still decrypt**

```bash
sops -d secrets/workspace-integrations.enc.yaml | grep drive-mcp-google-oauth-client-id
```

Expected: the real client ID prints (not `PLACEHOLDER_...`).

- [ ] **Step 3: Commit**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team add secrets/workspace-integrations.enc.yaml
git -C ~/git/RS/rs_infra_feat-drive-mcp-team commit -m "chore(secrets): populate drive-mcp OAuth client and signing key"
```

---

### Task 15: First manual apply (bootstrap)

**Not a code task — executed by an operator with owner-level permissions on `rs-workspace-integrations` and `kms-proj-a9dncstlc3zg`.**

Known risk: this is the step that previously blew up with CMEK errors. Watch for:
- `Permission denied on KMS key` → KMS project IAM missing; fix and re-run
- `Firestore encryption required` → `depends_on` missing on the Firestore resource (verify Task 5)
- `Managed SSL cert stuck in PROVISIONING` → DNS A record not propagated yet; wait 5–10 min

- [ ] **Step 1: `terragrunt plan`**

```bash
cd ~/git/RS/rs_infra_feat-drive-mcp-team/environments/non-production/workspace-integrations/drive-mcp
terragrunt plan -out=tfplan
```

Expected: plan shows ~30 resources to create, no errors.

- [ ] **Step 2: Review the plan**

Human review. Verify:
- All 4 KMS keys on `kms-proj-a9dncstlc3zg`
- Firestore database has `cmek_config`
- Cloud Run service has `encryption_key` set
- Secret Manager secrets have `customer_managed_encryption`
- All IAM bindings present

- [ ] **Step 3: `terragrunt apply`**

```bash
terragrunt apply tfplan
```

Expected: applies successfully. Note any resource that fails — if anything fails, STOP and fix before retrying.

- [ ] **Step 4: Verify managed cert provisions**

```bash
gcloud compute ssl-certificates describe drive-mcp-cert \
  --project=rs-workspace-integrations \
  --global \
  --format="value(managed.status)"
```

Expected: eventually prints `ACTIVE` (may take 10–30 min).

---

### Task 16: Smoke test

- [ ] **Step 1: Verify DNS resolves**

```bash
dig +short drive-mcp.relevantsearch.com
```

Expected: the LB IP from Task 15 output.

- [ ] **Step 2: Hit the hello-world via HTTPS**

```bash
curl -sSf https://drive-mcp.relevantsearch.com/
```

Expected: Cloud Run's hello-world HTML.

- [ ] **Step 3: Verify KMS bindings**

```bash
for key in cloud_run firestore secrets token; do
  echo "=== ${key} ==="
  gcloud kms keys get-iam-policy "drive-mcp-${key}" \
    --keyring=drive-mcp \
    --location=us-central1 \
    --project=kms-proj-a9dncstlc3zg
done
```

Expected: each key shows at least one `cryptoKeyEncrypterDecrypter` binding on the expected principal.

- [ ] **Step 4: Verify Firestore CMEK**

```bash
gcloud firestore databases describe \
  --database="(default)" \
  --project=rs-workspace-integrations \
  --format="value(cmekConfig.kmsKeyName)"
```

Expected: the full resource name of `drive-mcp-firestore` key.

---

### Task 17: Open PR

- [ ] **Step 1: Push the branch**

```bash
git -C ~/git/RS/rs_infra_feat-drive-mcp-team push -u origin feat/drive-mcp-team
```

- [ ] **Step 2: Open PR via `gh`**

```bash
gh pr create --title "feat(workspace-integrations): Drive MCP infrastructure" --body "$(cat <<'EOF'
## Summary

- New `workspace-integrations-mcp` Terragrunt module
- Nonprod env wiring in `environments/non-production/workspace-integrations/drive-mcp/`
- 4 KMS keys, Firestore CMEK, Cloud Run, serverless NEG LB, managed cert, Secret Manager

## Design

See `docs/projects/2026-04-15-drive-mcp-team/2026-04-15-drive-mcp-team-design.md`.

## Test plan

- [x] `tofu validate` + `tofu test` clean
- [x] Manual bootstrap apply completed successfully
- [x] DNS resolves + HTTPS serves hello-world
- [x] KMS IAM bindings verified on all 4 keys
- [x] Firestore `cmekConfig.kmsKeyName` populated

## Follow-up

- Plan 2 (app repo) replaces the hello-world image with the MCP server
EOF
)"
```

- [ ] **Step 3: Monitor CI**

```bash
gh pr checks <pr_number> --watch
```

If checks fail: diagnose, fix, push, re-monitor.

- [ ] **Step 4: Wait for review and merge**

Per CLAUDE.md: do NOT merge. Wait for Stefan to review and merge.

---

## Self-review

**Spec coverage:**

- CMEK on all services — Tasks 2, 3, 5, 6, 7, 8 ✓
- Firestore with `depends_on` — Task 5 ✓
- Serverless NEG (not Internet) — Task 9 ✓
- SOPS + Secret Manager — Task 7, 14 ✓
- Internal-only OAuth app — Task 13 ✓
- Custom domain + managed cert — Tasks 9, 10 ✓
- Terragrunt per-component isolation — Task 11 ✓
- No IAP — confirmed absent from Task 9 ✓
- First apply manual — Task 15 ✓
- v1 = nonprod only — only nonprod env created ✓

**Placeholder scan:** none.

**Type consistency:** `google_kms_crypto_key.key[...]` used consistently across tasks 2-10. Resource names consistent.

No gaps.

---

## Done criteria

Plan 1 is complete when:
- [ ] All 17 tasks complete
- [ ] PR merged
- [ ] `drive-mcp.relevantsearch.com` serves hello-world over HTTPS
- [ ] Plan 2 (app) can begin

## Changelog

### v1 — 2026-04-15
- Initial plan
