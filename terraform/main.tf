terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32"
    }
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "digitalocean" {
  token = var.digitalocean_token
}

resource "digitalocean_vpc" "centinell" {
  name   = "centinell-forensics-${var.environment}"
  region = var.digitalocean_region
}

resource "digitalocean_kubernetes_cluster" "centinell" {
  name     = "centinell-forensics-${var.environment}"
  region   = var.digitalocean_region
  version  = var.doks_version
  vpc_uuid = digitalocean_vpc.centinell.id

  node_pool {
    name       = "secure-workers"
    size       = var.doks_node_size
    node_count = 3
    auto_scale = true
    min_nodes  = 3
    max_nodes  = 6
  }
}

resource "digitalocean_database_cluster" "postgres" {
  name                 = "centinell-forensics-${var.environment}"
  engine               = "pg"
  version              = "16"
  size                 = var.database_size
  region               = var.digitalocean_region
  node_count           = 2
  private_network_uuid = digitalocean_vpc.centinell.id
}

resource "kubernetes_namespace" "centinell" {
  metadata {
    name = var.namespace
  }
}

resource "kubernetes_resource_quota" "centinell" {
  metadata {
    name      = "centinell-quota"
    namespace = kubernetes_namespace.centinell.metadata[0].name
  }
  spec {
    hard = {
      "requests.cpu"    = "4"
      "requests.memory" = "8Gi"
      "limits.cpu"      = "8"
      "limits.memory"   = "16Gi"
    }
  }
}
