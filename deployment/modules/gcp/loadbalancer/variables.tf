variable "project_id" {
  description = "GCP project ID where the loadbalancer is hosted."
  type        = string
}

variable "domain" {
  description = "Domain mapped to the load balancer."
  type        = string
}

variable "witnesses" {
  description = "Map of witnesses by name. This name will be used as the path component of the URL under 'domain' when mapping the provided witness service_name"
  type = map(object({
    service_name = string,
    region       = string,
  }))
}

variable "enable_cloud_armor" {
  description = "Whether or not to enable Cloud Armor for the load balancer."
  type        = bool
  default     = false
}
