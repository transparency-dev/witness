/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

# Project data
provider "google" {
  project = var.project_id
}

data "google_project" "project" {
  project_id = var.project_id
}

# This will be configured by terragrunt when deploying
terraform {
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.18.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "7.18.0"
    }
  }
}

# Enable Secret Manager API
resource "google_project_service" "secretmanager_api" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

# Enable Spanner
resource "google_project_service" "spanner_api" {
  service            = "spanner.googleapis.com"
  disable_on_destroy = false
}

# Enable Cloud Run API
resource "google_project_service" "cloudrun_api" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

data "google_secret_manager_secret" "witness_secret" {
  secret_id = var.witness_secret_name
}

data "google_secret_manager_secret_version" "witness_secret_data" {
  secret  = data.google_secret_manager_secret.witness_secret.id
  version = 1
}

# Update service accounts to allow secret access
resource "google_secret_manager_secret_iam_member" "secretaccess_compute_witness" {
  secret_id = data.google_secret_manager_secret.witness_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${data.google_project.project.number}-compute@developer.gserviceaccount.com" # Project's compute service account
}

resource "google_spanner_instance" "witness_spanner" {
  name             = "witness-${var.env}"
  config           = "regional-${var.region}"
  display_name     = "Witness ${var.env}"
  processing_units = 100

  force_destroy = var.ephemeral
  depends_on = [
    google_project_service.spanner_api,
  ]
}

resource "google_spanner_database" "witness_db" {
  instance = google_spanner_instance.witness_spanner.name
  name     = "witness_db_${var.env}"

  deletion_protection = !var.ephemeral
}

resource "google_spanner_database_iam_member" "database" {
  instance = google_spanner_instance.witness_spanner.name
  database = google_spanner_database.witness_db.name
  role     = "roles/spanner.databaseAdmin"

  member = "serviceAccount:${data.google_project.project.number}-compute@developer.gserviceaccount.com" # Project's compute service account
}

locals {
  spanner_db_full = "projects/${var.project_id}/instances/${google_spanner_instance.witness_spanner.name}/databases/${google_spanner_database.witness_db.name}"
}

# Set up an artifact registry to cache remote images we depend on via Cloud Run, below.
#
# This is intended to guard against the upstream image being unavailable for some reason.
resource "google_artifact_registry_repository" "witness" {
  location      = var.region 
  repository_id = "witness-remote-${var.env}"
  description   = "Remote repository with witness docker images upstream"
  format        = "DOCKER"
  mode          = "REMOTE_REPOSITORY"
  remote_repository_config {
    description = "Pull-through cache of witness repository"
    common_repository {
      uri         = var.witness_docker_repo
    }
  }
}

###
### Set up Cloud Run service
###

locals {
  public_witness_config_args = formatlist("--public_witness_config_url=%s", var.public_witness_config_urls)
}

resource "google_cloud_run_v2_service" "default" {
  name         = "witness-service-${var.env}"
  location     = var.region
  launch_stage = "GA"


  template {
    ## This Service account will be used for running the Cloud Run service which hosts the witness.
    ## 
    ## The service account provided here must be a member of the following roles in order to function properly:
    ##   "roles/iam.serviceAccountUser"
    ##   "roles/monitoring.metricWriter"
    ##   "roles/spanner.databaseUser"
    ##   "roles/run.serviceAgent"
    ##   "roles/secretmanager.secretAccessor"
    service_account = var.witness_service_account

    scaling {
      min_instance_count = 1
      max_instance_count = 3
    }
    max_instance_request_concurrency = 1000
    containers {
      # Access the witness docker image via our "pull-through" cache artifcat registry.
      image = "${google_artifact_registry_repository.witness.registry_uri}/${var.witness_docker_image}"
      name  = "witness"
      args = concat([
        "--logtostderr",
        "--v=1",
        "--listen=:8080",
        "--spanner=${local.spanner_db_full}",
        "--signer_private_key_secret_name=${data.google_secret_manager_secret_version.witness_secret_data.name}"
        ],
        local.public_witness_config_args,
      var.extra_args)
      ports {
        container_port = 8080
      }

      startup_probe {
        initial_delay_seconds = 1
        timeout_seconds       = 1
        period_seconds        = 10
        failure_threshold     = 3
        tcp_socket {
          port = 8080
        }
      }
    }
    containers {
      image      = "us-docker.pkg.dev/cloud-ops-agents-artifacts/cloud-run-gmp-sidecar/cloud-run-gmp-sidecar:1.3.0"
      name       = "collector"
      depends_on = ["witness"]
    }
  }
  client = "terraform"
  depends_on = [
    google_project_service.secretmanager_api,
    google_project_service.cloudrun_api,
    google_project_service.spanner_api,
  ]

  deletion_protection = !var.ephemeral
}

resource "google_cloud_run_service_iam_binding" "default" {
  location = google_cloud_run_v2_service.default.location
  service  = google_cloud_run_v2_service.default.name
  role     = "roles/run.invoker"
  members = [
    "allUsers"
  ]
}

