# Project data
provider "google" {
  project = var.project_id
}

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.50.0"
    }
  }

  backend "gcs" {}
}

module "gce-lb-http" {
  source                          = "terraform-google-modules/lb-http/google"
  version                         = "~> 12.0"
  name                            = "witness-${var.env}-lb-http"
  project                         = var.project_id
  load_balancing_scheme           = "EXTERNAL"
  ssl                             = true
  managed_ssl_certificate_domains = [var.domain]
  random_certificate_suffix       = true

  http_forward = false // HTTPS only

  // Firewalls are defined externally.
  firewall_networks = []

  create_url_map = false
  url_map        = google_compute_url_map.url_map.id

  // Use the Cloud Armor policy, if it's enabled.
  security_policy = one(module.cloud_armor[*].policy.self_link)

  backends = {
    for name, witness in var.witnesses :
    "${name}" => {
      protocol   = "HTTP"
      port       = 80
      port_name  = "http"
      enable_cdn = false

      // TODO(al): Decrease/remove this once it's working.
      log_config = {
        enable      = true
        sample_rate = 1.0
      }

      groups = [for region in witness.regions : {
        group = google_compute_region_network_endpoint_group.serverless_neg["${var.env}-${name}-${region}"].self_link
      }]

      iap_config = {
        enable = false
      }
    }
  }
}

resource "google_compute_region_network_endpoint_group" "serverless_neg" {
  # One NEG group per witness Cloud Run service.
  for_each = tomap({
    for witness in flatten([
      for witness_name, witness in var.witnesses : [
        for region in witness.regions : {
          name = witness_name
          witness = witness
          region  = region
        }
    ]]) : "${var.env}-${witness.name}-${witness.region}" => witness
  })

  #provider              = google-beta
  name                  = "${var.env}-${each.value.name}-${each.value.region}"
  network_endpoint_type = "SERVERLESS"
  region                = each.value.region
  cloud_run {
    service = each.value.witness.service_name
  }
}


resource "google_compute_url_map" "url_map" {
  name        = "witness-${var.env}-url-map"
  description = "URL map of witnesses"

  # Redirect requests to invalid endpoints to the witnesses page on transparency.dev
  default_url_redirect {
    host_redirect          = "transparency.dev"
    path_redirect          = "/witnesses"
    https_redirect         = true
    redirect_response_code = "FOUND" # Temporary redirect for now.
    strip_query            = true
  }

  dynamic "host_rule" {
    for_each = var.witnesses
    iterator = each

    content {
      hosts        = [var.domain]
      path_matcher = "${var.env}-${each.key}-path-matcher"
    }
  }

  dynamic "path_matcher" {
    for_each = var.witnesses
    iterator = each

    content {
      name = "${var.env}-${each.key}-path-matcher"

      # Redirect requests to invalid endpoints to the witnesses page on t.dev
      default_url_redirect {
        host_redirect          = "transparency.dev"
        path_redirect          = "/witnesses"
        redirect_response_code = "FOUND" # Temporary redirect for now.
        strip_query            = true
      }

      path_rule {
        paths   = ["/${each.key}/add-checkpoint"]
        service = module.gce-lb-http.backend_services[each.key].self_link
        route_action {
          url_rewrite {
            path_prefix_rewrite = "/add-checkpoint"
          }
        }
      }
    }
  }
}

module "cloud_armor" {
  source  = "GoogleCloudPlatform/cloud-armor/google"
  version = "~> 6.0"

  count                                = var.enable_cloud_armor ? 1 : 0
  project_id                           = var.project_id
  name                                 = "witness-${var.env}-security-policy"
  description                          = "Witness LB Security Policy"
  default_rule_action                  = "allow"
  type                                 = "CLOUD_ARMOR"
  layer_7_ddos_defense_enable          = true
  layer_7_ddos_defense_rule_visibility = "STANDARD"
}


