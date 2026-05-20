// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.simple.sign.client.tsb;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.crypto.Algorithm;

import com.fasterxml.jackson.databind.JsonNode;
import com.securosys.simple.sign.client.HsmClient;
import com.securosys.simple.sign.client.HsmKeyAttributes;
import com.securosys.simple.sign.client.config.TsbConfig;
import com.securosys.simple.sign.client.dto.request.CertificateIssueOptions;
import com.securosys.simple.sign.client.dto.request.CreateKeyDto;
import com.securosys.simple.sign.client.dto.result.DecryptResult;
import com.securosys.simple.sign.client.dto.result.SignResult;
import com.securosys.simple.sign.client.enums.CipherAlgorithm;
import com.securosys.simple.sign.client.enums.SignatureAlgorithm;
import com.securosys.simple.sign.client.tsb.dto.request.SynchronousDecryptEnvelope;
import com.securosys.simple.sign.client.tsb.dto.request.SynchronousDecryptRequest;
import com.securosys.simple.sign.client.tsb.dto.request.SynchronousSignEnvelope;
import com.securosys.simple.sign.client.tsb.dto.request.SynchronousSignRequest;
import com.securosys.simple.sign.client.tsb.dto.response.SynchronousDecryptResponse;
import com.securosys.simple.sign.client.tsb.dto.response.SynchronousSignResponse;
import com.securosys.simple.sign.client.tsb.key.KeyAttributes;
import com.securosys.simple.sign.client.tsb.key.KeyOperations;
import com.securosys.simple.sign.client.util.HsmUtil;

/**
 * Single TSB client object. Operation methods live in parent classes split by area.
 */
public class TsbClient extends KeyOperations implements HsmClient {
    protected TsbClient(String hostURL, HttpClient httpClient, AuthStruct auth) {
        super(hostURL, httpClient, auth);
    }

    /**
     * Initialize a TSB client from TsbConfig.
     */
    public TsbClient(TsbConfig config) throws Exception {
        super(config.getTsbUrl(), buildHttpClient(buildAuthFromTsbConfig(config)), buildAuthFromTsbConfig(config));
    }

    /**
     * Build AuthStruct from TsbConfig.
     */
    private static AuthStruct buildAuthFromTsbConfig(TsbConfig config) throws Exception {
        if (config == null) {
            throw new IllegalArgumentException("TSB configuration was null");
        }

        // Create ApiKeyTypes from the API keys in TsbConfig
        ApiKeyTypes apiKeys = new ApiKeyTypes();
        if (config.getKeyOperationApiKey() != null && !config.getKeyOperationApiKey().trim().isEmpty()) {
            apiKeys.setKeyOperationToken(java.util.Arrays.asList(config.getKeyOperationApiKey().split(",")));
        }
        if (config.getKeyManagementApiKey() != null && !config.getKeyManagementApiKey().trim().isEmpty()) {
            apiKeys.setKeyManagementToken(java.util.Arrays.asList(config.getKeyManagementApiKey().split(",")));
        }

        return new AuthStruct(
            config.getAuth(),
            config.getMtlsP12Path(),      // p12Path
            config.getMtlsP12Password(),  // p12Password
            config.getBearerToken(),      // bearerToken
            null,                         // basicToken (not used in TsbConfig)
            null,                         // username (not used in TsbConfig)
            null,                         // password (not used in TsbConfig)
            new KeyPair(),                // keyPair (empty for now)
            apiKeys,
            "Keycloak Securosys TSB Provider" // appName
        );
    }

    @Override
    public HsmKeyAttributes fetchKeyAttributes(String keyLabel, String keyPassword) throws Exception {
        KeyAttributes attributes = getKeyAttributes(keyLabel, keyPassword);
        return new HsmKeyAttributes(
                attributes.getLabel(),
                attributes.getAlgorithm(),
                attributes.getPublicKey(),
                attributes.getXml(),
                attributes.getXmlSignature(),
                attributes.getAttestationKeyName());
    }

    @Override
    public PublicKey getPublicKey(HsmKeyAttributes keyAttributes) {
        byte[] publicKeyBytes = Base64.getDecoder().decode(keyAttributes.getPublicKey());
        return HsmUtil.parsePublicKey(publicKeyBytes, keyAttributes.getAlgorithm());
    }

    @Override
    public SignResult createSignature(byte[] payload, String keyName, String password, String algorithm,
            String signatureType) throws Exception {
        SynchronousSignRequest request = new SynchronousSignRequest();
        request.setSignKeyName(keyName);
        request.setKeyPassword(password);
        request.setPayload(Base64.getEncoder().encodeToString(payload));
        request.setSignatureAlgorithm(mapSignatureAlgorithm(algorithm));
        request.setSignatureType(signatureType);

        String jsonBody = objectMapper.writeValueAsString(new SynchronousSignEnvelope(request));
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/synchronousSign"))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        ResponseData response = doRequest(httpRequest, KeyOperationTokenName);
        SynchronousSignResponse signResponse = readSynchronousSignResponse(response.getBody());
        return new SignResult(
                Base64.getDecoder().decode(signResponse.getSignature()),
                decodeOptionalBase64(signResponse.getPublicNonce()));
    }

    @Override
    public DecryptResult decrypt(String encryptedPayload, String keyName, String password, String cipherAlgorithm)
            throws Exception {
        SynchronousDecryptRequest request = new SynchronousDecryptRequest();
        request.setEncryptedPayload(encryptedPayload);
        request.setDecryptKeyName(keyName);
        request.setKeyPassword(password);
        request.setCipherAlgorithm(mapCipherAlgorithm(cipherAlgorithm));

        String jsonBody = objectMapper.writeValueAsString(new SynchronousDecryptEnvelope(request));
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/synchronousDecrypt"))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        ResponseData response = doRequest(httpRequest, KeyOperationTokenName);
        SynchronousDecryptResponse decryptResponse = readSynchronousDecryptResponse(response.getBody());
        return new DecryptResult(Base64.getDecoder().decode(decryptResponse.getPayload()));
    }

    @Override
    public void createKey(CreateKeyDto createKeyDto) throws Exception {
        if (createKeyDto == null) {
            throw new IllegalArgumentException("CreateKeyDto cannot be null");
        }
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("label", createKeyDto.getLabel());
        requestBody.put("password", createKeyDto.getPassword() == null ? null : new String(createKeyDto.getPassword()));
        requestBody.put("algorithm", createKeyDto.getAlgorithm());
        requestBody.put("curveOid", createKeyDto.getCurveOid());
        requestBody.put("keySize", createKeyDto.getKeySize());
        requestBody.put("attributes", createKeyDto.getAttributes());
        requestBody.put("id", createKeyDto.getId());
        requestBody.put("algorithmOid", createKeyDto.getAlgorithmOid());
        requestBody.put("addressFormat", createKeyDto.getAddressFormat());
        requestBody.put("policy", createKeyDto.getPolicy());

        String jsonBody = objectMapper.writeValueAsString(requestBody);
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/key"))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        doRequest(httpRequest, KeyManagementTokenName);
    }

    @Override
    public boolean checkIfKeyExists(String keyLabel, String password) throws Exception {
        try {
            this.fetchKeyAttributes(keyLabel, password);
            return true;
        }catch (Exception e) {
            return false;
        }
    }

    @Override
    public void deleteKey(String keyLabel, String password) throws Exception {
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("label", keyLabel);
        requestBody.put("password", password);

        String jsonBody = objectMapper.writeValueAsString(requestBody);
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/key/deleteKey"))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        doRequest(httpRequest, KeyManagementTokenName);
    }

    @Override
    public String getCertFromHsm(String keyLabel, String cname, String caKeyName) throws Exception {
        if (keyLabel == null || keyLabel.isBlank()) {
            return null;
        }

        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/certificate/" + keyLabel))
            .GET()
            .build();

        try {
            ResponseData response = doRequest(httpRequest, KeyManagementTokenName);
            JsonNode root = objectMapper.readTree(response.getBody());
            String certificate = root.has("rawCertificate") ? root.get("rawCertificate").asText(null) : null;
            return normalizeCertificate(certificate);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public String doSelfSignedCertificate(String keyLabel, String username) throws Exception {
        if (keyLabel == null || keyLabel.isBlank()) {
            throw new IllegalArgumentException("Key label is required for TSB self-signed certificate generation");
        }

        Map<String, Object> standardCertificateAttributes = new HashMap<>();
        standardCertificateAttributes.put("commonName", username);

        Map<String, Object> selfSignCertificateRequest = new HashMap<>();
        selfSignCertificateRequest.put("signKeyName", keyLabel);
        selfSignCertificateRequest.put("validity", 3650);
        selfSignCertificateRequest.put("signatureAlgorithm", "SHA256_WITH_RSA");
        selfSignCertificateRequest.put("standardCertificateAttributes", standardCertificateAttributes);
        selfSignCertificateRequest.put("keyUsage", java.util.List.of("DIGITAL_SIGNATURE"));
        selfSignCertificateRequest.put("extendedKeyUsage", java.util.List.of("ANY_EXTENDED_KEY_USAGE"));
        selfSignCertificateRequest.put("certificateAuthority", true);

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("selfSignCertificateRequest", selfSignCertificateRequest);

        String jsonBody = objectMapper.writeValueAsString(requestBody);
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/certificate/selfsign"))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        ResponseData response = doRequest(httpRequest, KeyManagementTokenName);
        JsonNode root = objectMapper.readTree(response.getBody());
        String signRequestId = root.has("signRequestId") ? root.get("signRequestId").asText(null) : null;
        if (signRequestId == null || signRequestId.isBlank()) {
            throw new IOException("TSB self-signed certificate request did not return signRequestId: " + response.getBody());
        }

        return waitForExecutedRequest(signRequestId);
    }

    @Override
    public String issueSignedCertificate(String keyLabel, CertificateIssueOptions options) throws Exception {
        if (keyLabel == null || keyLabel.isBlank()) {
            throw new IllegalArgumentException("Key label is required for TSB certificate issuance");
        }
        if (options == null || options.getCaKeyName() == null || options.getCaKeyName().isBlank()) {
            throw new IllegalArgumentException("CA key name is required for TSB certificate issuance");
        }

        String certificateSigningRequest = generateCertificateSigningRequest(keyLabel, options);

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("keyName", keyLabel);
        requestBody.put("signKeyName", options.getCaKeyName());
        requestBody.put("validity", options.getValidity());
        requestBody.put("signatureAlgorithm", options.getSignatureAlgorithm());
        requestBody.put("standardCertificateAttributes", standardCertificateAttributes(options));
        requestBody.put("certificateSigningRequest", certificateSigningRequest);
        requestBody.put("keyUsage", options.getKeyUsage());
        requestBody.put("extendedKeyUsage", options.getExtendedKeyUsage());
        requestBody.put("certificateAuthority", options.isCertificateAuthority());

        String jsonBody = objectMapper.writeValueAsString(requestBody);
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/certificate/synchronous/sign"))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        ResponseData response = doRequest(httpRequest, KeyManagementTokenName);
        JsonNode root = objectMapper.readTree(response.getBody());
        String certificate = root.has("certificate") ? root.get("certificate").asText(null) : null;
        if (certificate == null && root.has("rawCertificate")) {
            certificate = root.get("rawCertificate").asText(null);
        }
        String normalized = normalizeCertificate(certificate);
        if (normalized != null) {
            return normalized;
        }
        return getCertFromHsm(keyLabel, options.getCommonName(), options.getCaKeyName());
    }

    @Override
    public String generateCertificateSigningRequest(String keyLabel, CertificateIssueOptions options) throws Exception {
        if (keyLabel == null || keyLabel.isBlank()) {
            throw new IllegalArgumentException("Key label is required for TSB CSR generation");
        }
        CertificateIssueOptions requestOptions = options == null ? new CertificateIssueOptions() : options;

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("signKeyName", keyLabel);
        requestBody.put("signatureAlgorithm", requestOptions.getSignatureAlgorithm());
        requestBody.put("standardCertificateAttributes", standardCertificateAttributes(requestOptions));
        requestBody.put("keyUsage", requestOptions.getKeyUsage());
        requestBody.put("extendedKeyUsage", requestOptions.getExtendedKeyUsage());

        String jsonBody = objectMapper.writeValueAsString(requestBody);
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/certificate/synchronous/request"))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        ResponseData response = doRequest(httpRequest, KeyManagementTokenName);
        JsonNode root = objectMapper.readTree(response.getBody());
        if (root.has("certificateSigningRequest")) {
            return root.get("certificateSigningRequest").asText();
        }
        if (root.has("csr")) {
            return root.get("csr").asText();
        }
        return response.getBody();
    }

    @Override
    public String importCertificate(String keyLabel, String certificate) {
        return normalizeCertificate(certificate);
    }

    private Map<String, Object> standardCertificateAttributes(CertificateIssueOptions options) {
        Map<String, Object> attributes = new HashMap<>();
        putIfPresent(attributes, "commonName", options.getCommonName());
        putIfPresent(attributes, "country", options.getCountry());
        putIfPresent(attributes, "stateOrProvinceName", options.getStateOrProvinceName());
        putIfPresent(attributes, "locality", options.getLocality());
        putIfPresent(attributes, "organizationName", options.getOrganizationName());
        putIfPresent(attributes, "organizationIdentifier", options.getOrganizationIdentifier());
        putIfPresent(attributes, "organizationUnitName", options.getOrganizationUnitName());
        putIfPresent(attributes, "email", options.getEmail());
        putIfPresent(attributes, "title", options.getTitle());
        putIfPresent(attributes, "surname", options.getSurname());
        putIfPresent(attributes, "givenName", options.getGivenName());
        putIfPresent(attributes, "initials", options.getInitials());
        putIfPresent(attributes, "pseudonym", options.getPseudonym());
        putIfPresent(attributes, "generationQualifier", options.getGenerationQualifier());
        return attributes;
    }

    private void putIfPresent(Map<String, Object> attributes, String key, String value) {
        if (value != null && !value.isBlank()) {
            attributes.put(key, value);
        }
    }

    private String waitForExecutedRequest(String requestId) throws Exception {
        int attempts = 60;
        long delayMillis = 2000L;

        for (int attempt = 1; attempt <= attempts; attempt++) {
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(getHostURL() + "/v1/request/" + requestId))
                .GET()
                .build();

            ResponseData response = doRequest(httpRequest, KeyManagementTokenName);
            JsonNode root = objectMapper.readTree(response.getBody());
            String status = root.has("status") ? root.get("status").asText(null) : null;

            if ("EXECUTED".equalsIgnoreCase(status)) {
                String result = root.has("result") ? root.get("result").asText(null) : null;
                if (result == null || result.isBlank()) {
                    throw new IOException("TSB request " + requestId + " executed without certificate result: " + response.getBody());
                }
                return normalizeCertificate(result);
            }

            if ("PENDING".equalsIgnoreCase(status)) {
                Thread.sleep(delayMillis);
                continue;
            }

            throw new IOException("TSB request " + requestId + " failed with status " + status + ": " + response.getBody());
        }

        throw new IOException("Timed out waiting for TSB request " + requestId + " to execute");
    }

    private String normalizeCertificate(String certificate) {
        if (certificate == null || certificate.isBlank()) {
            return null;
        }

        String normalized = certificate.trim();
        if (normalized.contains("-----BEGIN CERTIFICATE-----")) {
            normalized = normalized
                .replaceAll("(?m)^-----BEGIN CERTIFICATE-----", "")
                .replaceAll("(?m)^-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        }
        return normalized;
    }

    private SynchronousSignResponse readSynchronousSignResponse(String body) throws Exception {
        JsonNode root = objectMapper.readTree(body);
        JsonNode payload = root.has("signResponse") ? root.get("signResponse") : root;
        return objectMapper.treeToValue(payload, SynchronousSignResponse.class);
    }

    private SynchronousDecryptResponse readSynchronousDecryptResponse(String body) throws Exception {
        JsonNode root = objectMapper.readTree(body);
        JsonNode payload = root.has("decryptResponse") ? root.get("decryptResponse") : root;
        return objectMapper.treeToValue(payload, SynchronousDecryptResponse.class);
    }

    private byte[] decodeOptionalBase64(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return Base64.getDecoder().decode(value);
    }

    private String mapSignatureAlgorithm(String algorithm) {
        if (algorithm == null) {
            return null;
        }
        return switch (algorithm) {
            case Algorithm.RS256, "SHA256withRSA" -> "SHA256_WITH_RSA";
            case Algorithm.RS384, "SHA384withRSA" -> "SHA384_WITH_RSA";
            case Algorithm.RS512, "SHA512withRSA" -> "SHA512_WITH_RSA";
            case Algorithm.ES256, "SHA256withECDSA" -> "SHA256_WITH_ECDSA";
            case Algorithm.ES384, "SHA384withECDSA" -> "SHA384_WITH_ECDSA";
            case Algorithm.ES512, "SHA512withECDSA" -> "SHA512_WITH_ECDSA";
            default -> SignatureAlgorithm.toTsbAlgorithm(algorithm);
        };
    }

    private String mapCipherAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) {
            return null;
        }
        return CipherAlgorithm.fromNameOrAlgorithm(algorithm).name();
    }
}
