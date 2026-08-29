terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.32" }
  }
}
provider "kubernetes" { config_path = var.kubeconfig_path }
resource "kubernetes_namespace" "centinell" {
  metadata { name = var.namespace }
}
resource "kubernetes_resource_quota" "centinell" {
  metadata {
    name      = "centinell-quota"
    namespace = kubernetes_namespace.centinell.metadata[0].name
  }
  spec { hard = { "requests.cpu" = "4", "requests.memory" = "8Gi", "limits.cpu" = "8", "limits.memory" = "16Gi" } }
}
