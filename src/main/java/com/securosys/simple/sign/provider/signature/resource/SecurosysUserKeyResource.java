/**
 * Copyright (c)2026 Securosys SA, authors: Tomasz Madej
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 **/
/**
 * Resource implementation for SecurosysUserKeyResource.
 */

package com.securosys.simple.sign.provider.signature.resource;

import com.securosys.simple.sign.client.HsmClient;
import com.securosys.simple.sign.client.HsmClientFactory;
import com.securosys.simple.sign.client.config.Config;
import com.securosys.simple.sign.client.dto.request.CertificateIssueOptions;
import com.securosys.simple.sign.client.dto.result.DecryptResult;
import com.securosys.simple.sign.client.dto.result.SignResult;
import com.securosys.simple.sign.client.enums.CipherAlgorithm;
import com.securosys.simple.sign.client.enums.SignatureAlgorithm;
import com.securosys.simple.sign.client.util.HsmConfigUtil;
import com.securosys.simple.sign.provider.signature.resource.record.CertificateImportRequest;
import com.securosys.simple.sign.provider.signature.resource.record.CertificateRequest;
import com.securosys.simple.sign.provider.signature.resource.record.DecryptRequest;
import com.securosys.simple.sign.provider.signature.resource.record.SignRequest;
import io.vertx.core.json.JsonObject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

import java.io.IOException;

/**
 * Resource class providing endpoints for fetching the page and calling the signing procedure.
 * It handles user authentication, HSM certificate retrieval, and signing operations.
 */
public class SecurosysUserKeyResource {

    private static final Logger LOGGER = Logger.getLogger(SecurosysUserKeyResource.class);
    private static final String DEFAULT_CLIENT_ID = "account-console";
    private static final String SIGNATURE_CLIENT_ID = "SIGNATURE_CLIENT_ID";
    private static final String MOBILE_APP_ENABLED = "Yes";
    private static final String DESKTOP_SIGNING = "No";
    private static final String STATUS_UPDATED = "updated";
    private final KeycloakSession session;

    public SecurosysUserKeyResource(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Endpoint in order to create a JWT which includes an arbitrary payload.
     * The user calling this endpoint has to be in a session.
     *
     * @param signRequest Record of type {@code SignRequest}
     * @return In case of correct credentials and valid session it will return an OK (200) response with the signed JWT ({@code PayloadToken})
     * else it returns a Forbidden (403) response
     */
    @POST
    @Path("/sign")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response sign(SignRequest signRequest) throws IOException {
        LOGGER.debugf("sign: /sign (POST) endpoint called");

        AuthenticationManager.AuthResult authResult = authenticateBearerToken();
        if (authResult == null || authResult.getUser() == null) {
            LOGGER.debugf("sign: No valid Bearer Token present");
            return Response.status(401).build();
        }

        final UserModel userModel = authResult.getUser();
        JsonObject signedPayloadJson = createAndSerializeSignature(signRequest, userModel);
        if (signedPayloadJson == null) {
            return Response.noContent().build();
        }
        return Response.ok(signedPayloadJson).build();
    }

    @POST
    @Path("/decrypt")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response decrypt(DecryptRequest decryptRequest) {
        LOGGER.debugf("decrypt: /decrypt (POST) endpoint called");

        AuthenticationManager.AuthResult authResult = authenticateBearerToken();
        if (authResult == null || authResult.getUser() == null) {
            LOGGER.debugf("decrypt: No valid Bearer Token present");
            return Response.status(401).build();
        }
        if (decryptRequest == null
                || decryptRequest.encryptedPayload() == null
                || decryptRequest.encryptedPayload().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(JsonObject.of("error", "encryptedPayload is required"))
                    .build();
        }

        try {
            JsonObject decryptedPayloadJson = createAndSerializeDecrypt(decryptRequest, authResult.getUser());
            if (decryptedPayloadJson == null) {
                return Response.noContent().build();
            }
            return Response.ok(decryptedPayloadJson).build();
        } catch (Exception e) {
            LOGGER.error("decrypt: decrypt operation failed", e);
            return Response.serverError()
                    .entity(JsonObject.of("error", errorMessage(e)))
                    .build();
        }
    }

    @POST
    @Path("/certificate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response certificate(CertificateRequest certificateRequest) {
        LOGGER.debugf("certificate: /certificate (POST) endpoint called");

        AuthenticationManager.AuthResult authResult = authenticateBearerToken();
        if (authResult == null || authResult.getUser() == null) {
            LOGGER.debugf("certificate: No valid Bearer Token present");
            return Response.status(401).build();
        }

        UserModel userModel = authResult.getUser();
        String keyLabel = getUserKeyLabel(userModel);
        HsmClient hsmClient = createHsmClient("certificate");
        if (hsmClient == null) {
            return Response.noContent().build();
        }

        try {
            SecurosysUserKeyResourceProviderFactory.updateKeyAttributes(userModel, hsmClient, keyLabel);

            boolean issueCertificate = certificateRequest != null
                    && Boolean.TRUE.equals(certificateRequest.issueCertificate());
            if (issueCertificate) {
                CertificateIssueOptions options = toCertificateIssueOptions(certificateRequest, userModel);
                if (options.getCaKeyName() == null || options.getCaKeyName().isBlank()) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity(JsonObject.of("error", "caKeyName is required when issueCertificate is true"))
                            .build();
                }

                String issuedCertificate = hsmClient.issueSignedCertificate(keyLabel, options);
                if (issuedCertificate == null || issuedCertificate.isBlank()) {
                    SecurosysUserKeyResourceProviderFactory.updateKeyAttributes(userModel, hsmClient, keyLabel);
                } else {
                    SecurosysUserKeyResourceProviderFactory.setCertificateAttributes(userModel, issuedCertificate);
                }
            }

            return Response.ok(JsonObject.of(
                    "keyName", keyLabel,
                    "certificate", userModel.getFirstAttribute(SecurosysUserKeyResourceProviderFactory.CERTIFICATE),
                    "selfSigned", userModel.getFirstAttribute(SecurosysUserKeyResourceProviderFactory.SELF_SIGNED)
            )).build();
        } catch (Exception e) {
            LOGGER.error("certificate: certificate operation failed", e);
            return Response.serverError()
                    .entity(JsonObject.of("error", errorMessage(e)))
                    .build();
        }
    }

    @POST
    @Path("/certificate/csr")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response certificateSigningRequest(CertificateRequest certificateRequest) {
        LOGGER.debugf("certificate: /certificate/csr (POST) endpoint called");

        AuthenticationManager.AuthResult authResult = authenticateBearerToken();
        if (authResult == null || authResult.getUser() == null) {
            LOGGER.debugf("certificate: No valid Bearer Token present");
            return Response.status(401).build();
        }

        UserModel userModel = authResult.getUser();
        String keyLabel = getUserKeyLabel(userModel);
        HsmClient hsmClient = createHsmClient("certificate-csr");
        if (hsmClient == null) {
            return Response.noContent().build();
        }

        try {
            CertificateIssueOptions options = toCertificateIssueOptions(certificateRequest, userModel);
            String csr = hsmClient.generateCertificateSigningRequest(keyLabel, options);
            return Response.ok(JsonObject.of(
                    "keyName", keyLabel,
                    "certificateSigningRequest", csr
            )).build();
        } catch (Exception e) {
            LOGGER.error("certificate: CSR generation failed", e);
            return Response.serverError()
                    .entity(JsonObject.of("error", errorMessage(e)))
                    .build();
        }
    }

    @POST
    @Path("/certificate/import")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response importCertificate(CertificateImportRequest certificateImportRequest) {
        LOGGER.debugf("certificate: /certificate/import (POST) endpoint called");

        AuthenticationManager.AuthResult authResult = authenticateBearerToken();
        if (authResult == null || authResult.getUser() == null) {
            LOGGER.debugf("certificate: No valid Bearer Token present");
            return Response.status(401).build();
        }
        if (certificateImportRequest == null
                || certificateImportRequest.certificate() == null
                || certificateImportRequest.certificate().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(JsonObject.of("error", "certificate is required"))
                    .build();
        }

        UserModel userModel = authResult.getUser();
        String keyLabel = getUserKeyLabel(userModel);
        HsmClient hsmClient = createHsmClient("certificate-import");
        if (hsmClient == null) {
            return Response.noContent().build();
        }

        try {
            String importedCertificate = hsmClient.importCertificate(keyLabel, certificateImportRequest.certificate());
            if (importedCertificate == null || importedCertificate.isBlank()) {
                importedCertificate = certificateImportRequest.certificate();
            }
            SecurosysUserKeyResourceProviderFactory.setCertificateAttributes(userModel, importedCertificate);
            return Response.ok(JsonObject.of(
                    "keyName", keyLabel,
                    "certificate", userModel.getFirstAttribute(SecurosysUserKeyResourceProviderFactory.CERTIFICATE),
                    "selfSigned", userModel.getFirstAttribute(SecurosysUserKeyResourceProviderFactory.SELF_SIGNED)
            )).build();
        } catch (Exception e) {
            LOGGER.error("certificate: certificate import failed", e);
            return Response.serverError()
                    .entity(JsonObject.of("error", errorMessage(e)))
                    .build();
        }
    }

    public AuthenticationManager.AuthResult authenticateBearerToken() {
        return new org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator(session)
                .authenticate();
    }


    private boolean isAuthorizedKeyName(UserModel userModel, String requestedKeyName) {
        String authorizedKeyName = userModel.getFirstAttribute(SecurosysUserKeyResourceProviderFactory.KEY_LABEL);
        return requestedKeyName != null && requestedKeyName.equals(authorizedKeyName);
    }



    public JsonObject createAndSerializeSignature(SignRequest signRequest, UserModel userModel) throws IOException {
        HsmClient hsmClient = createHsmClient("sign");
        if (hsmClient == null) {
            return null;
        }

        String keyLabel = getUserKeyLabel(userModel);
        String signatureAlgorithm = signRequest.signatureAlgorithm();
        if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
            signatureAlgorithm = SignatureAlgorithm.SHA256_WITH_RSA;
        }
        SignResult signature = null;
        try {
            signature = hsmClient.createSignature(
                    Base64.decode(signRequest.payload()),
                    keyLabel,
                    null,
                    signatureAlgorithm,
                    "DER"
            );
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }


        return serializeSignatureResponse(signature);
    }

    public JsonObject createAndSerializeDecrypt(DecryptRequest decryptRequest, UserModel userModel) throws Exception {
        HsmClient hsmClient = createHsmClient("decrypt");
        if (hsmClient == null) {
            return null;
        }

        String keyLabel = getUserKeyLabel(userModel);
        String algorithm = decryptRequest.cipherAlgorithm();
        if (algorithm == null || algorithm.isBlank()) {
            algorithm = CipherAlgorithm.RSA_PADDING_OAEP_WITH_SHA512.name();
        }

        DecryptResult decryptResult = hsmClient.decrypt(
                decryptRequest.encryptedPayload(),
                keyLabel,
                null,
                algorithm
        );
        return serializeDecryptResponse(decryptResult);
    }

    private HsmClient createHsmClient(String operation) {
        Config config = HsmConfigUtil.getHsmConfig(session);
        if (config == null) {
            LOGGER.debugf("%s: skipping operation because no active Securosys HSM configuration was found", operation);
            return null;
        }
        try {
            HsmClient hsmClient = HsmClientFactory.create(config);
            if (hsmClient == null) {
                LOGGER.debugf("%s: skipping operation because HSM client was null", operation);
            }
            return hsmClient;
        } catch (Exception e) {
            LOGGER.debugf(e, "%s: skipping operation because HSM client could not be created", operation);
            return null;
        }
    }

    private CertificateIssueOptions toCertificateIssueOptions(CertificateRequest request, UserModel userModel) {
        CertificateIssueOptions options = new CertificateIssueOptions();
        if (request == null) {
            options.setCommonName(userModel.getUsername());
            return options;
        }

        options.setCaKeyName(request.caKeyName());
        options.setCommonName(firstNonBlank(request.commonName(), userModel.getUsername()));
        options.setCountry(request.country());
        options.setStateOrProvinceName(request.stateOrProvinceName());
        options.setLocality(request.locality());
        options.setOrganizationName(request.organizationName());
        options.setOrganizationIdentifier(request.organizationIdentifier());
        options.setOrganizationUnitName(request.organizationUnitName());
        options.setEmail(request.email());
        options.setTitle(request.title());
        options.setSurname(request.surname());
        options.setGivenName(request.givenName());
        options.setInitials(request.initials());
        options.setPseudonym(request.pseudonym());
        options.setGenerationQualifier(request.generationQualifier());
        if (request.validity() != null) {
            options.setValidity(request.validity());
        }
        if (request.signatureAlgorithm() != null && !request.signatureAlgorithm().isBlank()) {
            options.setSignatureAlgorithm(request.signatureAlgorithm());
        }
        if (request.keyUsage() != null && !request.keyUsage().isEmpty()) {
            options.setKeyUsage(request.keyUsage());
        }
        if (request.extendedKeyUsage() != null && !request.extendedKeyUsage().isEmpty()) {
            options.setExtendedKeyUsage(request.extendedKeyUsage());
        }
        if (request.certificateAuthority() != null) {
            options.setCertificateAuthority(request.certificateAuthority());
        }

        return options;
    }

    private String firstNonBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private String errorMessage(Exception e) {
        Throwable cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        String message = cause.getMessage();
        return message == null || message.isBlank() ? cause.toString() : message;
    }

    private String getUserKeyLabel(UserModel userModel) {
        String keyLabel = userModel.getFirstAttribute(SecurosysUserKeyResourceProviderFactory.KEY_LABEL);
        if (keyLabel == null || keyLabel.isEmpty()) {
            throw new IllegalStateException("KeyLabel is empty. Please refresh user first using endpoint /onboard");
        }
        return keyLabel;
    }


    private JsonObject serializeSignatureResponse(SignResult signResult) throws IOException {
        return JsonObject.of(
                "signature", Base64.encodeBytes(signResult.getSignature())
        );
    }

    private JsonObject serializeDecryptResponse(DecryptResult decryptResult) throws IOException {
        return JsonObject.of(
                "payload", Base64.encodeBytes(decryptResult.getPayload())
        );
    }

}
