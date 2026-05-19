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
 * Keycloak event listener implementation for SecurosysEventListener.
 */

package com.securosys.simple.sign.provider.event;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.securosys.simple.sign.client.HsmClient;
import com.securosys.simple.sign.client.HsmClientFactory;
import com.securosys.simple.sign.client.config.Config;
import com.securosys.simple.sign.client.dto.request.CreateKeyDto;
import com.securosys.simple.sign.client.jce.dto.AttributesDto;
import com.securosys.simple.sign.client.util.HsmConfigUtil;
import com.securosys.simple.sign.provider.signature.resource.SecurosysUserKeyResourceProviderFactory;

/**
 * Keycloak event listener that responds to user profile updates by automatically
 * generating HSM keys for digital signing when users are onboarded.
 *
 * Triggered on:
 * - UPDATE_PROFILE: User profile changes (triggers HSM key generation if needed)
 */
public class SecurosysEventListener implements EventListenerProvider {
    private static final Logger logger = Logger.getLogger(SecurosysEventListener.class);
    private final KeycloakSession session;
    private final HsmClient hsmClient;

    public SecurosysEventListener(KeycloakSession session) {
        this.session = session;
        HsmClient client = null;
        try {
            Config config = HsmConfigUtil.getHsmConfig(session);
            if (config == null) {
                logger.debug("[HSM-EVENT] HSM client not initialized because no active Securosys HSM configuration was found");
            } else {
                client = HsmClientFactory.create(config);
                if (client == null) {
                    logger.debug("[HSM-EVENT] HSM client not initialized because factory returned null");
                }
            }
        } catch (Exception e) {
            logger.debugf(e, "[HSM-EVENT] HSM client not initialized");
        }
        this.hsmClient = client;
    }

    /**
     * Processes HSM triggers based on event type.
     * For UPDATE_PROFILE events, checks if user needs HSM key generation.
     */
    @Override
    public void onEvent(Event event) {
        logger.infof("[HSM-EVENT] %s",event.getType());
        if (event.getType() == EventType.UPDATE_PROFILE) {
            processHsmTrigger(event.getRealmId(), event.getUserId());
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        logger.infof("[HSM-ADMIN-EVENT] type=%s resourceType=%s path=%s realm=%s includeRepresentation=%s",
                event.getOperationType(), event.getResourceType(), event.getResourcePath(), event.getRealmId(), includeRepresentation);

        if (event.getResourceType() == ResourceType.USER && event.getOperationType() == OperationType.UPDATE
        || event.getResourceType() == ResourceType.USER && event.getOperationType() == OperationType.CREATE) {
            String userId = extractUserIdFromResourcePath(event.getResourcePath());
            if (userId != null) {
                processHsmTrigger(event.getRealmId(), userId);
            }
        }
    }

    private String extractUserIdFromResourcePath(String resourcePath) {
        if (resourcePath == null || resourcePath.isBlank()) {
            return null;
        }
        String[] parts = resourcePath.split("/");
        if (parts.length >= 2 && "users".equals(parts[0])) {
            return parts[1];
        }
        return null;
    }

    /**
     * Triggers HSM key generation if user is configured for desktop signing
     * (not mobile app mode).
     *
     * @param realmId Keycloak realm identifier
     * @param userId User ID to process
     */
    private void processHsmTrigger(String realmId, String userId) {
        UserModel user = getUserFromEvent(realmId, userId);
        if (user == null) {
            return;
        }

        generateHsmKeyForUser(user);
    }

    private UserModel getUserFromEvent(String realmId, String userId) {
        RealmModel realm = session.realms().getRealm(realmId);
        return session.users().getUserById(realm, userId);
    }

    private void generateHsmKeyForUser(UserModel user) {
        if (hsmClient == null) {
            logger.debugf("[HSM-EVENT] Skipping HSM key generation for %s because HSM client is not available",
                    user.getUsername());
            return;
        }

        try {
            String existingKeyLabel = user.getFirstAttribute(SecurosysUserKeyResourceProviderFactory.KEY_LABEL);

            logger.infof("[HSM-EVENT] Triggering HSM Key Generation for %s", user.getUsername());


            // If KEY_LABEL was empty, create key and update it
            if (existingKeyLabel == null || existingKeyLabel.isBlank()) {
                String newKeyLabel= user.getUsername()+"_key";
                if(hsmClient.checkIfKeyExists(newKeyLabel,null)){
                    user.setSingleAttribute(SecurosysUserKeyResourceProviderFactory.KEY_LABEL, newKeyLabel);
                    SecurosysUserKeyResourceProviderFactory.updateKeyAttributes(user, hsmClient, newKeyLabel);

                }else {

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
                    createKeyDto.getAttributes().setUnwrap(true);
                    createKeyDto.getAttributes().setVerify(true);
                    createKeyDto.getAttributes().setExtractable(false);
                    createKeyDto.getAttributes().setSensitive(true);
                    hsmClient.createKey(createKeyDto);
                    user.setSingleAttribute(SecurosysUserKeyResourceProviderFactory.KEY_LABEL, newKeyLabel);
                    SecurosysUserKeyResourceProviderFactory.updateKeyAttributes(user, hsmClient, newKeyLabel);
                }
            } else {
                if(hsmClient.checkIfKeyExists(existingKeyLabel,null)){
                    SecurosysUserKeyResourceProviderFactory.updateKeyAttributes(user, hsmClient, existingKeyLabel);

                }else{

                    CreateKeyDto createKeyDto = new CreateKeyDto();
                    createKeyDto.setKeySize(2048);
                    createKeyDto.setLabel(existingKeyLabel);
                    createKeyDto.setAlgorithm("RSA");
                    createKeyDto.setPassword(null);
                    createKeyDto.setAttributes(new AttributesDto());
                    createKeyDto.getAttributes().setDestroyable(true);
                    createKeyDto.getAttributes().setDecrypt(true);
                    createKeyDto.getAttributes().setEncrypt(true);
                    createKeyDto.getAttributes().setUnwrap(true);
                    createKeyDto.getAttributes().setSign(true);
                    createKeyDto.getAttributes().setVerify(true);
                    createKeyDto.getAttributes().setExtractable(false);
                    createKeyDto.getAttributes().setSensitive(true);
                    hsmClient.createKey(createKeyDto);
                    user.setSingleAttribute(SecurosysUserKeyResourceProviderFactory.KEY_LABEL, existingKeyLabel);
                    SecurosysUserKeyResourceProviderFactory.updateKeyAttributes(user, hsmClient, existingKeyLabel);

                }
            }

            logger.info("[HSM-EVENT] HSM attributes updated successfully.");
        } catch (Exception e) {
            logger.error("[HSM-EVENT-ERROR] Failed to generate HSM key: " + e.getMessage());
        }
    }

    @Override
    public void close() {}
}
