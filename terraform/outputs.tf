output "namespace" {
  value = kubernetes_namespace.centinell.metadata[0].name
}
output "doks_cluster_id" {
  value = digitalocean_kubernetes_cluster.centinell.id
}
output "database_host" {
  value     = digitalocean_database_cluster.postgres.private_host
  sensitive = true
}
