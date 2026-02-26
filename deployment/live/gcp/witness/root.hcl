terraform {
  source = "${get_repo_root()}/deployment/modules/gcp/witness"
}

locals {
  project_id = "checkpoint-distributor"
  regions   = ["us-central1"]
  env        = path_relative_to_include()
}

remote_state {
  backend = "gcs"

  config = {
    project  = local.project_id
    location = local.regions[0]
    bucket   = "${local.project_id}-witness-${local.env}-terraform-state"
    prefix   = "${path_relative_to_include()}/terraform.tfstate"

    gcs_bucket_labels = {
      name = "terraform_state_storage"
    }
  }
}
