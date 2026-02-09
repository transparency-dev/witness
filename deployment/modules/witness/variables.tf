/**
 * Copyright 2019 Google LLC
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

variable "project_id" {
  description = "The project ID to host the cluster in"
  type        = string
}

variable "region" {
  description = "The region to host the cluster in"
  type        = string
}

variable "env" {
  description = "Unique identifier for the env, e.g. ci or prod"
  type        = string
}

variable "witness_docker_repo" {
  description = "The full URL of the docker registry where the witness docker image can be found"
  type        = string
}

variable "witness_docker_image" {
  description = "The image name and tag of the witness docker image to deploy, as found on the witness_docker_repo."
  type        = string
}

variable "extra_args" {
  description = "Extra arguments to be provided to the witness invoked in cloud run"
  type        = list(string)
  default     = []
}

variable "ephemeral" {
  description = "Set to true if this is a CI/temporary deploy"
  type        = bool
  default     = false
}

variable "public_witness_config_urls" {
  description = "Set to a list of URLs where public witness config files can be retrieved"
  type        = list(string)
  default     = []
}

variable "witness_service_account" {
  description = "Service account identifier to use when running the witness. Should be in email form: 'email@address'. This service will need to be a member of several IAM roles - see the main.tf for details."
  type        = string
}

variable "witness_secret_name" {
  description = "Secret manager secret name containing the note-formatted key to use for signing checkpoints."
  type        = string
}
