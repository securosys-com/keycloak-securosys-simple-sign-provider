# Keycloak Securosys HSM Simple Sign Provider

Keycloak Securosys HSM Simple Sign Provider extends
[securosys-com/keycloak-securosys-hsm-provider](https://github.com/securosys-com/keycloak-securosys-hsm-provider).
This module does not work standalone. The base Securosys HSM provider must be installed and configured in Keycloak,
because this module reuses its HSM/JCE/TSB configuration and client integration.

The module adds a realm endpoint for signing arbitrary Base64 payloads with a user's HSM key:

```text
POST /realms/{realm}/user_key/sign
POST /realms/{realm}/user_key/certificate
POST /realms/{realm}/user_key/certificate/csr
POST /realms/{realm}/user_key/certificate/import
```

Signing operations run externally on HSM. Certificate information is stored on the Keycloak user.

Plugin support for now:
- User payload signing using SHA256withRSA
- Automatic self-signed certificate creation for user HSM keys
- CSR generation for external CA/PKI signing
- Import of externally issued certificates
- CA/PKI certificate issuing using a configured HSM/TSB CA key
- HSM connection using Securosys JCE through the base provider
- HSM connection using Securosys TSB REST API through the base provider
- Automatic user key setup when an active Securosys HSM provider is configured

>**NOTE** - If no active Securosys HSM provider configuration is found, this module skips HSM key generation,
> signature creation, and key cleanup. Those operations are logged on debug level.

## Prerequisites

You need:
- [Docker](https://docs.docker.com/engine/install/) or Keycloak instance
- Java installed
- [securosys-com/keycloak-securosys-hsm-provider](https://github.com/securosys-com/keycloak-securosys-hsm-provider) installed in the same Keycloak instance

## Build

```sh
./gradlew clean providerDist -x test
```

The build creates a provider distribution in **build/provider-dist**:
- **build/provider-dist/provider** - Keycloak Securosys HSM Simple Sign provider jar
- **build/provider-dist/lib** - runtime dependency jars, for example **primus-jce**

>**Note** - task **providerDist** is also executed by **build** and **test**.

## Installing Procedure

Install the base provider first:
[securosys-com/keycloak-securosys-hsm-provider](https://github.com/securosys-com/keycloak-securosys-hsm-provider).

All jars from **build/provider-dist/provider** and **build/provider-dist/lib** have to be copied into the same
Keycloak **providers** directory. Do not keep the **provider** and **lib** subdirectories in Keycloak.

Example target layout:

```text
/opt/keycloak/providers/keycloak-securosys-hsm-provider-1.0.0.jar
/opt/keycloak/providers/keycloak-securosys-hsm-simple-sign-1.0.0.jar
/opt/keycloak/providers/primus-jce-2.5.4.jar
/opt/keycloak/providers/...
```

Keycloak automatically recognizes the new provider and adds it to UI.

For the first time or update provider jar in logs will be visible similar lines:

```sh
keycloak-1  | Updating the configuration and installing your custom providers, if any. Please wait.
keycloak-1  | 2026-01-22 12:29:17,147 WARN  [org.key.services] (build-19) KC-SERVICES0047: RS256 (com.securosys.hsm.provider.signature.algorithm.RS256) is implementing the internal SPI signature. This SPI is internal and may change without notice
keycloak-1  | 2026-01-22 12:29:17,148 WARN  [org.key.services] (build-19) KC-SERVICES0047: ES256 (com.securosys.hsm.provider.signature.algorithm.ES256) is implementing the internal SPI signature. This SPI is internal and may change without notice
keycloak-1  | 2026-01-22 12:29:17,453 WARN  [org.key.services] (build-19) KC-SERVICES0047: securosys-hsm-jce (com.securosys.hsm.provider.key.SecurosysJceKeyProviderFactory) is implementing the internal SPI keys. This SPI is internal and may change without notice
keycloak-1  | 2026-01-22 12:29:17,454 WARN  [org.key.services] (build-19) KC-SERVICES0047: securosys-hsm-tsb (com.securosys.hsm.provider.key.SecurosysTsbKeyProviderFactory) is implementing the internal SPI keys. This SPI is internal and may change without notice
```

That means, provider is successfully added to Keycloak.

## Configuration

Configure the base Securosys HSM provider first. Key provider configuration is documented in
[securosys-com/keycloak-securosys-hsm-provider](https://github.com/securosys-com/keycloak-securosys-hsm-provider).

Then enable this module's event listener in Keycloak:
1. Open **Realm settings**
2. Open **Events**
3. Add **securosys-hsm-simple-sign-listener** to **Event listeners**
4. Save the realm settings

The listener handles user create/update/delete events and keeps the user's HSM key attributes in sync.

## User Key Attributes

This module adds user profile attributes:
- **securosys_user_key_name** - HSM key label assigned to the user
- **securosys_certificate** - read-only certificate field
- **securosys_self_signed** - read-only self-signed certificate information, **Yes** or **No**

When a user is created or updated and an active HSM provider exists, the module creates or refreshes the user's HSM key.
The module reads the existing HSM certificate. If the key does not have a certificate yet, it creates a self-signed
certificate and marks **securosys_self_signed** as **Yes**. If a CA/PKI-issued certificate is imported or issued, the
module stores the new certificate and marks **securosys_self_signed** according to the certificate content.
If HSM is not configured, the operation is skipped and logged on debug level.

## Sign Endpoint

Get a Keycloak access token for the user:

```sh
ACCESS_TOKEN=$(curl -sS \
  -d "client_id=<client-id>" \
  -d "username=<username>" \
  -d "password=<password>" \
  -d "grant_type=password" \
  "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  | jq -r ".access_token")
```

Sign a Base64 payload:

```sh
curl -X POST "http://localhost:8080/realms/master/user_key/sign" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"payload":"aGVsbG8="}'
```

Successful response:

```json
{
  "signature": "base64-signature"
}
```

If no active Securosys HSM configuration or HSM client is available, the endpoint returns **204 No Content**.

## Certificate Endpoints

Certificate endpoints use the same Bearer token as the sign endpoint. They operate on the HSM key assigned to the
authenticated user through **securosys_user_key_name**.

### Ensure Certificate

This endpoint makes sure the user key has a certificate. By default it creates a self-signed certificate when the HSM key
has no certificate yet.

```sh
curl -X POST "http://localhost:8080/realms/master/user_key/certificate" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Successful response:

```json
{
  "keyName": "<user-key-name>",
  "certificate": "base64-certificate",
  "selfSigned": "Yes"
}
```

### Issue Certificate With HSM/TSB CA

To replace the self-signed certificate with a CA/PKI-issued certificate, pass **issueCertificate** with the HSM/TSB CA
key name.

```sh
curl -X POST "http://localhost:8080/realms/master/user_key/certificate" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "issueCertificate": true,
    "caKeyName": "<ca-key-name>",
    "commonName": "<common-name>",
    "validity": 3650,
    "signatureAlgorithm": "SHA256_WITH_RSA",
    "keyUsage": ["DIGITAL_SIGNATURE"],
    "extendedKeyUsage": ["ANY_EXTENDED_KEY_USAGE"],
    "certificateAuthority": false
  }'
```

Successful response:

```json
{
  "keyName": "<user-key-name>",
  "certificate": "base64-certificate",
  "selfSigned": "No"
}
```

For this flow, **caKeyName** must be an HSM/TSB key that can issue certificates.

### Generate CSR For External CA

For an external CA/PKI flow, export a CSR from the user's HSM key. The external CA private key is not imported into
Keycloak or HSM. Only the issued certificate is imported/stored later. Signing still uses the user's HSM key.

```sh
curl -X POST "http://localhost:8080/realms/master/user_key/certificate/csr" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "commonName": "<common-name>",
    "country": "<country-code>",
    "stateOrProvinceName": "<state-or-province>",
    "locality": "<locality>",
    "organizationName": "<organization-name>",
    "organizationIdentifier": "<organization-identifier>",
    "organizationUnitName": "<organization-unit>",
    "email": "<email-address>",
    "title": "<title>",
    "surname": "<surname>",
    "givenName": "<given-name>",
    "initials": "<initials>",
    "pseudonym": "<pseudonym>",
    "generationQualifier": "<generation-qualifier>",
    "signatureAlgorithm": "SHA256_WITH_RSA",
    "keyUsage": ["DIGITAL_SIGNATURE"],
    "extendedKeyUsage": ["ANY_EXTENDED_KEY_USAGE"]
  }'
```

Successful response:

```json
{
  "keyName": "<user-key-name>",
  "certificateSigningRequest": "-----BEGIN NEW CERTIFICATE REQUEST-----\n...\n-----END NEW CERTIFICATE REQUEST-----\n"
}
```

### Import External Certificate

After the customer signs the CSR with their own CA, import the issued certificate:

```sh
curl -X POST "http://localhost:8080/realms/master/user_key/certificate/import" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }'
```

Successful response:

```json
{
  "keyName": "<user-key-name>",
  "certificate": "base64-certificate",
  "selfSigned": "No"
}
```

### Certificate Request Fields

Fields used by **/certificate** with **issueCertificate=true**:

| Field | Required | Description |
| --- | --- | --- |
| **issueCertificate** | Yes | Set to **true** to issue a CA/PKI certificate instead of only ensuring a self-signed certificate exists. |
| **caKeyName** | Yes | HSM/TSB key label of the CA key used to sign the certificate. |
| **commonName** | No | Certificate subject common name. Defaults to the Keycloak username when omitted. |
| **validity** | No | Certificate validity in days. Default is **3650**. |
| **signatureAlgorithm** | No | RSA signature algorithm used for the certificate or CSR. Default is **SHA256_WITH_RSA**. |
| **keyUsage** | No | List of X.509 key usage values. Default is **DIGITAL_SIGNATURE**. |
| **extendedKeyUsage** | No | List of X.509 extended key usage values. Default is **ANY_EXTENDED_KEY_USAGE**. |
| **certificateAuthority** | No | Whether the issued certificate is a CA certificate. For user signing certificates use **false**. |

Fields used by **/certificate/csr**:

| Field | Required | Description |
| --- | --- | --- |
| **commonName** | No | Subject common name. Defaults to the Keycloak username when omitted. |
| **country** | No | Subject country value, usually a two-letter country code such as **CH**. |
| **stateOrProvinceName** | No | Subject state or province. |
| **locality** | No | Subject locality or city. |
| **organizationName** | No | Subject organization name. |
| **organizationIdentifier** | No | Subject organization identifier. |
| **organizationUnitName** | No | Subject organizational unit. |
| **email** | No | Subject email address. |
| **title** | No | Subject title. |
| **surname** | No | Subject surname. |
| **givenName** | No | Subject given name. |
| **initials** | No | Subject initials. |
| **pseudonym** | No | Subject pseudonym. |
| **generationQualifier** | No | Subject generation qualifier, for example **Jr**. |
| **signatureAlgorithm** | No | RSA signature algorithm used for CSR signing. Default is **SHA256_WITH_RSA**. |
| **keyUsage** | No | List of X.509 key usage values. Default is **DIGITAL_SIGNATURE**. |
| **extendedKeyUsage** | No | List of X.509 extended key usage values. Default is **ANY_EXTENDED_KEY_USAGE**. |

Fields used by **/certificate/import**:

| Field | Required | Description |
| --- | --- | --- |
| **certificate** | Yes | PEM certificate or Base64/DER certificate issued for the user's HSM key. |

### Key Usage Values

Use enum names in JSON:

| Value | X.509 value | Description |
| --- | --- | --- |
| **DIGITAL_SIGNATURE** | digitalSignature | Certificate can be used for digital signatures. |
| **CONTENT_COMMITMENT** | contentCommitment | Certificate can be used for non-repudiation/content commitment. |
| **KEY_ENCIPHERMENT** | keyEncipherment | Certificate can be used to encipher keys. |
| **DATA_ENCIPHERMENT** | dataEncipherment | Certificate can be used to encipher data. |
| **KEY_AGREEMENT** | keyAgreement | Certificate can be used for key agreement. |
| **KEY_CERT_SIGN** | keyCertSign | Certificate can be used to sign certificates. Usually for CA certificates. |
| **CRL_SIGN** | cRLSign | Certificate can be used to sign CRLs. Usually for CA certificates. |
| **ENCIPHER_ONLY** | encipherOnly | Certificate can be used only for enciphering during key agreement. |
| **DECIPHER_ONLY** | decipherOnly | Certificate can be used only for deciphering during key agreement. |

Example:

```json
"keyUsage": ["DIGITAL_SIGNATURE"]
```

### Extended Key Usage Values

Use enum names in JSON:

| Value | X.509 value | Description |
| --- | --- | --- |
| **ANY_EXTENDED_KEY_USAGE** | anyExtendedKeyUsage | Certificate can be used for any extended key usage. |
| **SERVER_AUTH** | serverAuth | TLS server authentication. |
| **CLIENT_AUTH** | clientAuth | TLS client authentication. |
| **CODE_SIGNING** | codeSigning | Code signing. |
| **EMAIL_PROTECTION** | emailProtection | Email protection. |
| **TIME_STAMPING** | timeStamping | Time stamping. |
| **OCSP_SIGNING** | OCSPSigning | OCSP response signing. |

Example:

```json
"extendedKeyUsage": ["ANY_EXTENDED_KEY_USAGE"]
```

### Signature Algorithm Values

Only RSA certificate/CSR signature algorithms are supported by this module for now. Use enum names in JSON:

| Value | JCE algorithm |
| --- | --- |
| **SHA224_WITH_RSA** | SHA224withRSA |
| **SHA256_WITH_RSA** | SHA256withRSA |
| **SHA384_WITH_RSA** | SHA384withRSA |
| **SHA512_WITH_RSA** | SHA512withRSA |

Example:

```json
"signatureAlgorithm": "SHA256_WITH_RSA"
```

## Test

Test commands run Keycloak in Docker, copy all jars from **build/provider-dist/provider** and
**build/provider-dist/lib** into one flat container directory, **/opt/keycloak/providers**, configure the provider,
and test lifecycle signing:

```sh
./gradlew clean test
```

The lifecycle tests cover:
- Keycloak provider loading
- User HSM key generation
- Default self-signed certificate creation
- CSR generation
- CA-issued certificate creation with a configured CA-capable HSM/TSB key
- User payload signing
- User/key cleanup
- JCE and TSB configurations

The CA-issued certificate endpoint requires a valid HSM/TSB CA key name in **caKeyName**. It should be tested with a
real CA-capable key in the target HSM/TSB environment.
