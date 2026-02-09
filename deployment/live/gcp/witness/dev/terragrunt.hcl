include "root" {
  path   = find_in_parent_folders("root.hcl")
  expose = true
}

inputs = merge(
  include.root.locals,
  {
    public_witness_config_urls = ["https://raw.githubusercontent.com/transparency-dev/witness-network/refs/heads/main/lists/testing/log-list.1"]
    witness_docker_repo        = "https://ghcr.io"
    witness_docker_image       = "transparency-dev/witness/omniwitness_gcp:latest"
    witness_secret_name        = "witness_secret_dev"
    witness_service_account    = "cloudrun-witness-dev-sa@checkpoint-distributor.iam.gserviceaccount.com"

    ephemeral = true
  }
)

