output "namespace" {
  value = kubernetes_namespace.centinell.metadata[0].name
}
