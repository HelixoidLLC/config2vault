backend "inmem" {
    scheme = "https"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = "false"
  tls_key_file = "/vault/ssl/vault_server.key"
  tls_cert_file = "/vault/ssl/vault_server.crt"
}
