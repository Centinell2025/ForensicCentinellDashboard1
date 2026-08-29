variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}
variable "namespace" {
  type    = string
  default = "centinell-forensics"
}
variable "digitalocean_token" {
  type      = string
  sensitive = true
}
variable "digitalocean_region" {
  type    = string
  default = "nyc3"
}
variable "environment" {
  type    = string
  default = "production"
}
variable "doks_version" {
  type    = string
  default = "1.33.1-do.3"
}
variable "doks_node_size" {
  type    = string
  default = "s-2vcpu-4gb"
}
variable "database_size" {
  type    = string
  default = "db-s-2vcpu-4gb"
}
