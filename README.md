# Description

  _config2vault_ is the foundation of the "Immutable Security" and an extention of the "Immutable Infrastructure".
It is used to "seed" Vault with the configuration from sources like source control and ensure that there are no
deviations from such configuration.
 
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
 make integration
 ```
