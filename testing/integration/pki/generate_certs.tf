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
}
