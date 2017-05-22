# Description

  _config2vault_ is the foundation of the "Immutable Security" and an extention of the "Immutable Infrastructure".
It is used to "seed" Vault with the configuration from sources like source control and ensure that there are no
deviations from such configuration.

**Important to understand** the fact that _config2vault_ converges all the rules. This means that it'll ensure that
the state of Vault is exactly matching to the rules. If the configuration is not present in Vault, it'll be created
and if the configuration is present in Vault but not in the rules, it'll be removed and a WARNING will be raised.
 
  The deviations that are hapenning in the configuration are either the natural lifecycle of the system
(ex: deprecation of a policy) or an indentification of a **security breach** (ex: unexpected token created).
 _config2vault_ is designed to identify such "deviations" and raise a **warning** in such a case so the security
 monitoring can react to such events.
 
 **Note:** we're using LastPass as a source of all the secrets to seed from
 
 # Getting Started
 
 _config2vault_ will injest and converge all the rules from the specified file or folder. If the source is a folder, 
 _config2vault_ will enumerate all the *.yml and *.yaml files it'll find.
 
 ```
 ./config2vault -config config.json rules_folder_or_file
 ```
 
 _config2vault_ needs at least:
  1. URL to Vault server
  1. Sudo token with full administrative rights. Since the tool is designed to control all aspects of Vault, the 
  token has to have appropriate rights.  
 
 These values can be specified in a ```config``` file or via environment variables:
 
 ```
 export VAULT_ADDR=http://192.168.99.100:8200
 export VAULT_TOKEN=03a26f25-bfdc-6cc7-2bde-52153e0e0b7f
 ```
 
Ex: Config file example
 ```
 {
   "url": "http://192.168.99.100:8200",
   "token": "03a26f25-bfdc-6cc7-2bde-52153e0e0b7f"
 }
 ```
 
 ### Available Config file options
 
 You can have an advanced configuration only via configuration file. The following options are available:
 
 * path - path to rules file or the rules folder
 * url - http or https url with port to the Vault API endpoint
 * token - Vault token with administrative rights
 * ca_file - path to CA certificate
 * cert_file - path to Vault client certificate
 * key_file - path to Vault client key

## Configuring Secret Backends

### Consul Secret Backend

Example for configuring [Consul Secret Backend](https://www.vaultproject.io/docs/secrets/consul/index.html):

```
mounts:
  - type: consul
    description: Consul backend
    policy_base64_encode: true
    config:
      - path: access
        properties:
          address: 192.168.99.100:8500
          token: a49e7360-f150-463a-9a29-3eb186ffae1a
          
roles:
  - name: readonly
    path: consul
    properties:
      policy: |
        key "" {
          policy = "read"
        }
```

### Generic Secret Backend

Example for configuring [Generic Secret Backend](https://www.vaultproject.io/docs/secrets/generic/index.html):

```
secrets:
  - path: deploy/secret
    fields:
      - key: pass
        value: hello
```

### PKI Secret Backend

Example for configuring [PKI Secret Backend](https://www.vaultproject.io/docs/secrets/pki/index.html):

```
mounts:
  - type: pki
    max_lease_ttl: 87600h
    config:
      - path: ca
        ca_bundle:
          key: "@ssl/ca.key"
          cert: "@ssl/ca.crt"
          
roles:
  - name: example-dot-com
    path: pki
    properties:
      allowed_domains: example.com
      allow_subdomains: true
      max_ttl: 72h
```

### PostgreSQL Secret Backend

Example for configuring [PostgreSQL Secret Backend](https://www.vaultproject.io/docs/secrets/postgresql/index.html):

```
mounts:
  - type: postgresql
    description: Postgres backend
    path: myPostgres
    config:
      - path: connection
        properties:
          connection_url: postgresql://postgres:password@192.168.99.100:5432/postgres?sslmode=disable
      - path: lease
        properties:
          lease: 1h
          lease_max: 24h
          
roles:
  - name: readonly
    path: myPostgres
    properties:
      sql: |
        CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";
```

### SSH Secret Backend

Example for configuring [SSH Secret Backend](https://www.vaultproject.io/docs/secrets/ssh/index.html):

```
mounts:
  - type: ssh
  
roles:
  - name: otp_key_role
    path: ssh
    properties:
      key_type: otp
      default_user: admin
      cidr_list: 10.135.0.0/16
      cidr_list: 192.168.99.0/24
```

### Transit encryption

Example for configuring [Transit Backend](https://www.vaultproject.io/docs/secrets/transit/index.html):

```
mounts:
  - type: transit
  
transit_keys:
  - name: foo
    type: aes256-gcm96

```

## Configuring Audit Backend
 
### AppRole Auth Backend

Example for configuring [AppRole Auth Backend](https://www.vaultproject.io/docs/auth/approle.html):

```
auth:
  - type: approle
  
approles:
  - role: role1
    policies:
      - pol1
      - pol2
    secret_id_ttl: 10m
    token_ttl: 20m
    token_max_ttl: 30m
    secret_id_num_uses :40
```

### Username & Password Auth Backend 

Example for configuring [Username & Password Auth Backend](https://www.vaultproject.io/docs/auth/userpass.html):

```
auth:
  - type: userpass
  
policies:
  - name: secret
    rules: |
      path "secret/*" {
        capabilities = ["create", "read", "update", "delete", "list"]
      }
      path "secret/super-secret" {
        capabilities = ["deny"]
      }
      
users:
  - name: john
    password: secret
    policies:
      - secret
```

# Developing config2vault
## Prerequisits for development environment

* Go
* Docker maching and Docker-compose configured
* make

## Building release bits

```
make build
```

## Running Integation test suite


```
export DOCKER_TLS_VERIFY=1
export DOCKER_MACHINE_NAME=name_of_your_working_docker_machine
export DOCKER_HOST=tcp://192.168.99.100:2376  <-- put your docker machine address
export DOCKER_CERT_PATH=/Users/your_account_name/.docker/machine/machines/name_of_your_working_docker_machine
make integration
```
If you're running on Mac and using "Docker for Mac" and not "Docker Toolbox" then you can use:
```
export DOCKER_HOST=unix:///var/run/docker.sock
```
