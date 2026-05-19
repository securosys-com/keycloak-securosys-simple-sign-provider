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
 * Resource implementation for SecurosysUserKeyResourceProviderFactory.
 */

package com.securosys.simple.sign.provider.signature.resource;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import com.securosys.simple.sign.client.HsmClient;
import com.securosys.simple.sign.client.HsmClientFactory;
import com.securosys.simple.sign.client.dto.request.CreateKeyDto;
import com.securosys.simple.sign.client.jce.dto.AttributesDto;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPAttributePermissions;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.keycloak.userprofile.UserProfileProvider;

import com.securosys.simple.sign.client.util.HsmConfigUtil;

/**
 * Factory for creating SecurosysUserKeyResourceProvider instances.
 * This factory also handles initialization and setup of user profile attributes
 * related to Securosys HSM keys and certificates.
 */
public class SecurosysUserKeyResourceProviderFactory implements RealmResourceProviderFactory {

    private static final Logger LOGGER = Logger.getLogger(SecurosysUserKeyResourceProviderFactory.class);
    private static final String ID = "user_key";
    public static final String KEY_LABEL = "securosys_user_key_name";
    public static final String CERTIFICATE = "securosys_certificate";
    public static final String SELF_SIGNED = "securosys_self_signed";
    public static final String SELF_SIGNED_YES = "Yes";
    public static final String SELF_SIGNED_NO = "No";

    /**
     * Returns the unique identifier for this provider factory.
     *
     * @return the provider ID
     */
    @Override
    public String getId() {
        return ID;
    }

    /**
     * Creates a new instance of the realm resource provider.
     *
     * @param keycloakSession the Keycloak session
     * @return a new SecurosysUserKeyResourceProvider instance
     */
    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new SecurosysUserKeyResourceProvider(keycloakSession);
    }

    /**
     * Initializes the factory with the given configuration scope.
     *
     * @param scope the configuration scope
     */
    @Override
    public void init(Config.Scope scope) {

    }

    /**
     * Performs post-initialization tasks, such as registering event listeners
     * for setting up user profiles after migration.
     *
     * @param keycloakSessionFactory the Keycloak session factory
     */
    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        keycloakSessionFactory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                // Use the 'session' provided by the job lambda
                KeycloakModelUtils.runJobInTransaction(keycloakSessionFactory, session -> {
                    this.setupSecurosysUserProfile(session);
                });
            }
        });
    }

    /**
     * Converts a snake_case string to Camel Case with spaces.
     *
     * @param input the input string in snake_case
     * @return the converted string in Camel Case
     */
    private String toCamelCaseWithSpaces(String input) {
        if (input == null || input.isEmpty()) return input;

        StringBuilder result = new StringBuilder();
        for (String part : input.split("_")) {
            if (part.length() > 0) {
                result.append(Character.toUpperCase(part.charAt(0)))
                        .append(part.substring(1).toLowerCase())
                        .append(" ");
            }
        }
        return result.toString().trim();
    }

    /**
     * Updates the user profile configuration for the current realm by adding
     * necessary attributes for Securosys HSM integration.
     *
     * @param session the Keycloak session
     */
    private void updateUserProfileConfig(KeycloakSession session) {
        UserProfileProvider upProvider = session.getProvider(UserProfileProvider.class);
        if (upProvider == null) return;

        UPConfig config = upProvider.getConfiguration();
        boolean modified = false;

        // Configure KEY_LABEL - admin only editable, users can view
        if (config.getAttribute(KEY_LABEL) == null) {
            UPAttribute attr = new UPAttribute();
            attr.setName(KEY_LABEL);
            attr.setDisplayName(toCamelCaseWithSpaces(KEY_LABEL));
            UPAttributePermissions permissions = new UPAttributePermissions();
            permissions.setView(Set.of("admin", "user"));
            permissions.setEdit(Set.of("admin")); // Only admin can edit
            attr.setPermissions(permissions);
            attr.setMultivalued(false);
            config.addOrReplaceAttribute(attr);
            modified = true;
        }

        modified |= addReadOnlyAttribute(config, CERTIFICATE, Map.of("inputType", "textarea"));
        modified |= addReadOnlyAttribute(config, SELF_SIGNED, Map.of());


        if (modified) {
            upProvider.setConfiguration(config);
        }
    }

    private boolean addReadOnlyAttribute(UPConfig config, String attributeName, Map<String, Object> annotations) {
        if (config.getAttribute(attributeName) != null) {
            return false;
        }

        UPAttribute attr = new UPAttribute();
        attr.setName(attributeName);
        attr.setDisplayName(toCamelCaseWithSpaces(attributeName));
        if (!annotations.isEmpty()) {
            attr.setAnnotations(annotations);
        }
        UPAttributePermissions permissions = new UPAttributePermissions();
        permissions.setView(Set.of("admin", "user"));
        attr.setPermissions(permissions);
        attr.setMultivalued(false);
        config.addOrReplaceAttribute(attr);
        return true;
    }

    /**
     * Sets up the Securosys user profile for all realms after migration.
     * This includes updating user profile configurations and applying default attributes.
     *
     * @param session the Keycloak session
     */
    private void setupSecurosysUserProfile(KeycloakSession session) {
        String MARKER_ATTR = "securosys_setup_complete";

        // Create a list first to avoid "Stream is closed" issues during iteration
        List<RealmModel> realms = session.realms().getRealmsStream().toList();

        for (RealmModel realm : realms) {
            // CRITICAL: We need a dedicated context for each realm
            session.getContext().setRealm(realm);

            try {
                updateUserProfileConfig(session);

                if (realm.getAttribute(MARKER_ATTR) != null) continue;

                // Setup and create keys for existing users
                session.users().searchForUserStream(realm, "")
                        .forEach(user -> createKeyDynamically(session, user));

                realm.setAttribute(MARKER_ATTR, "true");
            } finally {
                session.getContext().setRealm(null);
            }
        }
    }

    /**
     * Creates an HSM key dynamically for a user if needed.
     * If KEY_LABEL is empty, uses user email as the key name.
     * If KEY_LABEL is provided, uses that name and creates key if it doesn't exist.
     *
     * @param session the Keycloak session
     * @param user the user model
     */
    private void createKeyDynamically(KeycloakSession session, UserModel user) {
        String keyLabel = user.getFirstAttribute(KEY_LABEL);

        try {
            com.securosys.simple.sign.client.config.Config config = HsmConfigUtil.getHsmConfig(session);
            if (config == null) {
                LOGGER.debugf("[HSM-SETUP] Skipping HSM key setup for user %s because no active Securosys HSM configuration was found",
                        user.getUsername());
                return;
            }

            HsmClient hsmClient = HsmClientFactory.create(config);
            if (hsmClient == null) {
                LOGGER.debugf("[HSM-SETUP] Skipping HSM key setup for user %s because HSM client is not available",
                        user.getUsername());
                return;
            }

            // If KEY_LABEL was empty, create key and update it
            if (keyLabel == null || keyLabel.isBlank()) {
                String newKeyLabel= user.getUsername()+"_key";

                CreateKeyDto createKeyDto = new CreateKeyDto();
                createKeyDto.setKeySize(2048);
                createKeyDto.setLabel(newKeyLabel);
                createKeyDto.setAlgorithm("RSA");
                createKeyDto.setPassword(null);
                createKeyDto.setAttributes(new AttributesDto());
                createKeyDto.getAttributes().setDestroyable(true);
                createKeyDto.getAttributes().setDecrypt(true);
                createKeyDto.getAttributes().setEncrypt(true);
                createKeyDto.getAttributes().setSign(true);
                createKeyDto.getAttributes().setVerify(true);
                createKeyDto.getAttributes().setExtractable(false);
                createKeyDto.getAttributes().setSensitive(true);
                hsmClient.createKey(createKeyDto);
                user.setSingleAttribute(KEY_LABEL, newKeyLabel);

                updateKeyAttributes(user, hsmClient, newKeyLabel);
            } else {
                if(hsmClient.checkIfKeyExists(keyLabel,null)){
                    updateKeyAttributes(user, hsmClient, keyLabel);

                }else{

                    CreateKeyDto createKeyDto = new CreateKeyDto();
                    createKeyDto.setKeySize(2048);
                    createKeyDto.setLabel(keyLabel);
                    createKeyDto.setAlgorithm("RSA");
                    createKeyDto.setPassword(null);
                    createKeyDto.setAttributes(new AttributesDto());
                    createKeyDto.getAttributes().setDestroyable(true);
                    createKeyDto.getAttributes().setDecrypt(true);
                    createKeyDto.getAttributes().setEncrypt(true);
                    createKeyDto.getAttributes().setSign(true);
                    createKeyDto.getAttributes().setVerify(true);
                    createKeyDto.getAttributes().setExtractable(false);
                    createKeyDto.getAttributes().setSensitive(true);
                    hsmClient.createKey(createKeyDto);
                    user.setSingleAttribute(KEY_LABEL, keyLabel);

                    updateKeyAttributes(user, hsmClient, keyLabel);

                }
            }
        } catch (Exception e) {
            LOGGER.debugf(e, "[HSM-SETUP] Skipping HSM key setup for user %s", user.getUsername());
        }
    }

    public static void updateKeyAttributes(UserModel user, HsmClient hsmClient, String keyLabel) throws Exception {
        String certificate = hsmClient.getCertFromHsm(keyLabel, user.getUsername(), null);
        if (certificate == null || certificate.isBlank()) {
            hsmClient.doSelfSignedCertificate(keyLabel, user.getUsername());
            certificate = hsmClient.getCertFromHsm(keyLabel, user.getUsername(), null);
            if (certificate != null && !certificate.isBlank()) {
                setCertificateAttributes(user, certificate, true);
                return;
            }
        } else {
            setCertificateAttributes(user, certificate);
            return;
        }
        user.setSingleAttribute(SELF_SIGNED, SELF_SIGNED_NO);
    }

    public static void setCertificateAttributes(UserModel user, String certificate) {
        setCertificateAttributes(user, certificate, isSelfSignedCertificate(certificate));
    }

    public static void setCertificateAttributes(UserModel user, String certificate, boolean selfSigned) {
        user.setSingleAttribute(CERTIFICATE, certificate);
        user.setSingleAttribute(SELF_SIGNED, selfSigned ? SELF_SIGNED_YES : SELF_SIGNED_NO);
    }

    public static boolean isSelfSignedCertificate(String certificateBase64) {
        try {
            byte[] certificateBytes = decodeCertificate(certificateBase64);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
                    new ByteArrayInputStream(certificateBytes));
            if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                return false;
            }
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception e) {
            LOGGER.debug("Could not determine whether certificate is self-signed", e);
            return false;
        }
    }

    private static byte[] decodeCertificate(String certificateBase64) {
        String certificate = certificateBase64.trim();
        if (certificate.contains("-----BEGIN CERTIFICATE-----")) {
            certificate = certificate
                    .replaceAll("(?m)^-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("(?m)^-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
        }
        try {
            return Base64.getDecoder().decode(certificate.getBytes(StandardCharsets.US_ASCII));
        } catch (IllegalArgumentException e) {
            return certificate.getBytes(StandardCharsets.UTF_8);
        }
    }

    /**
     * Closes the factory and releases any resources.
     */
    @Override
    public void close() {

    }
}
