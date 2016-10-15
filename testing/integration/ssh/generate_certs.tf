resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits = 2048
}

resource "tls_self_signed_cert" "ca" {
  key_algorithm = "${tls_private_key.ca.algorithm}"
  private_key_pem = "${tls_private_key.ca.private_key_pem}"
  validity_period_hours = 43800
  is_ca_certificate = "true"
  allowed_uses = ["cert_signing", "key_encipherment", "client_auth", "server_auth"]
  subject = {
    common_name = "*.vault"
    organization = "config2vault"
    organizational_unit = "config2vault"
    street_address = ["config2vault"]
    locality = "Needham"
    province = "MA"
    country = "USA"
    postal_code = "02492"
    serial_number = "1"
  }
}

#######################
##
##   Vault server
##
#######################

resource "tls_private_key" "vault_server" {
  algorithm = "RSA"
  rsa_bits = 2048
}

resource "tls_cert_request" "vault_server" {
  key_algorithm = "${tls_private_key.vault_server.algorithm}"
  private_key_pem = "${tls_private_key.vault_server.private_key_pem}"
  subject = {
    common_name = "Vault Server"
    organization = "config2vault"
    organizational_unit = "config2vault"
    street_address = ["config2vault"]
    locality = "Needham"
    province = "MA"
    country = "USA"
    postal_code = "02492"
    serial_number = "1"
  }
  dns_names = [
    "vault00.vault",
  ]
}

resource "tls_locally_signed_cert" "vault_server" {
  cert_request_pem = "${tls_cert_request.vault_server.cert_request_pem}"
  ca_key_algorithm = "${tls_private_key.ca.algorithm}"
  ca_private_key_pem = "${tls_private_key.ca.private_key_pem}"
  ca_cert_pem = "${tls_self_signed_cert.ca.cert_pem}"
  allowed_uses = ["key_encipherment", "server_auth"]
  validity_period_hours = 43800
}


#######################
##
##   Vault client
##
#######################

resource "tls_private_key" "vault_client" {
  algorithm = "RSA"
  rsa_bits = 2048
}

resource "tls_cert_request" "vault_client" {
  key_algorithm = "${tls_private_key.vault_client.algorithm}"
  private_key_pem = "${tls_private_key.vault_client.private_key_pem}"
  subject = {
    common_name = "Vault Client"
    organization = "config2vault"
    organizational_unit = "config2vault"
    street_address = ["config2vault"]
    locality = "Needham"
    province = "MA"
    country = "USA"
    postal_code = "02492"
    serial_number = "1"
  }
  dns_names = [
    "*.vault"
  ]
}

resource "tls_locally_signed_cert" "vault_client" {
  cert_request_pem = "${tls_cert_request.vault_client.cert_request_pem}"
  ca_key_algorithm = "${tls_private_key.ca.algorithm}"
  ca_private_key_pem = "${tls_private_key.ca.private_key_pem}"
  ca_cert_pem = "${tls_self_signed_cert.ca.cert_pem}"
  allowed_uses = ["key_encipherment", "digital_signature", "client_auth"]
  validity_period_hours = 43800
}

# Dump output
resource "null_resource" "dump" {
  provisioner "local-exec" {
    command = "mkdir -p ssl"
  }
  provisioner "local-exec" {
    command = "echo \"${tls_private_key.ca.private_key_pem}\" > ssl/ca.key"
  }
  provisioner "local-exec" {
    command = "echo \"${tls_self_signed_cert.ca.cert_pem}\" > ssl/ca.crt"
  }
  provisioner "local-exec" {
    command = "echo \"${tls_private_key.vault_server.private_key_pem}\" > ssl/vault_server.key"
  }
  provisioner "local-exec" {
    command = "echo \"${tls_locally_signed_cert.vault_server.cert_pem}\" > ssl/vault_server.crt"
  }
  provisioner "local-exec" {
    command = "echo \"${tls_private_key.vault_client.private_key_pem}\" > ssl/vault_client.key"
  }

  provisioner "local-exec" {
    command = "echo \"${tls_locally_signed_cert.vault_client.cert_pem}\" > ssl/vault_client.crt"
  }
}
