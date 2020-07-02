# HVS Installer

## Usage
```shell
./hvs-v3.0.0.bin
```

## env file

Category | Field | Required | Type | Default
---------|-------|----------|------|---------|
General | AAS_BASE_URL | `Required` | `string` | |
\- | CMS_BASE_URL | `Required` |`string` | |
\- | CMS_CERT_DIGEST | `Required` |`string` | |
\- | BEARER_TOKEN | `Required` |`string` | |
TLS | TLS_CERT_FILE | - |`string` | |
\- | TLS_KEY_FILE | - |`string` | |
\- | TLS_COMMON_NAME | - |`string` | |
\- | TLS_SAN_LIST | - |`string` | |
SAML | SAML_CERT_FILE | - |`string` | |
\- | SAML_KEY_FILE | - |`string` | |
\- | SAML_COMMON_NAME | - |`string` | |
Flavor Signing | FLAVOR_SIGNING_CERT_FILE | - |`string` || 
\- | FLAVOR_SIGNING_KEY_FILE | - |`string` | |
\- | FLAVOR_SIGNING_COMMON_NAME | - |`string` | |
Privacy CA | PRIVACY_CA_CERT_FILE | - |`string` | |
\- | PRIVACY_CA_KEY_FILE | - |`string` | |
\- | PRIVACY_CA_COMMON_NAME | - |`string` | |
\- | PRIVACY_CA_ISSUER | - |`string` | |
\- | PRIVACY_CA_VALIDITY_DAYS | - |`int` | |
Tag CA | TAG_CA_CERT_FILE | - |`string` | |
\- | TAG_CA_KEY_FILE | - |`string` | |
\- | TAG_CA_COMMON_NAME | - |`string` | |
\- | TAG_CA_ISSUER | - |`string` | |
\- | TAG_CA_VALIDITY_DAYS | - |`int` | |
Log | LOG_MAX_LENGTH | - |`int` | |
\- | LOG_ENABLE_STDOUT | - |`bool` | |
\- | LOG_LEVEL | - |`string` | |
Endorsement CA | ENDORSEMENT_CA_CERT_FILE | - |`string` | |
\- | ENDORSEMENT_CA_KEY_FILE | - |`string` | |
\- | ENDORSEMENT_CA_COMMON_NAME | - |`string` | |
\- | ENDORSEMENT_CA_ISSUER | - |`string` | |
\- | ENDORSEMENT_CA_VALIDITY_DAYS | - |`int` | |
Server | SERVER_PORT | - |`int` | |
\- | SERVER_READ_TIMEOUT | - |`Duration` | |
\- | SERVER_READ_HEADER_TIMEOUT | - |`Duration` | |
\- | SERVER_WRITE_TIMEOUT | - |`Duration` | |
\- | SERVER_IDLE_TIMEOUT | - |`Duration` | |
\- | SERVER_MAX_HEADER_BYTES | - |`int` | |
Database | DATABASE_VENDOR | `Required` |`string` | |
\- | DATABASE_HOST | `Required` |`string` | |
\- | DATABASE_PORT | `Required` |`int` | |
\- | DATABASE_DB_NAME | `Required` |`string` | |
\- | DATABASE_USERNAME | `Required` |`string` | |
\- | DATABASE_PASSWORD | `Required` |`string` | |
\- | DATABASE_SSL_MODE | - |`string` | |
\- | DATABASE_SSL_CERT | - |`string` | |
\- | DATABASE_SSL_CERT_SOURCE | - |`string` | |
\- | DATABASE_CONN_RETRY_ATTEMPTS | - |`int` | |
\- | DATABASE_CONN_RETRY_TIME | - |`int` | |
HRRS | HRRS_REFRESH_PERIOD | - |`Duration` | 2 minutes ("2m")|
\- | HRRS_REFRESH_LOOK_AHEAD | - |`Duration` | 5 minutes ("5m")|
