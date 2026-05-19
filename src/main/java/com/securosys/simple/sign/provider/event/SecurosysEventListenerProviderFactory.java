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

package com.securosys.simple.sign.provider.event;

import com.securosys.simple.sign.client.HsmClient;
import com.securosys.simple.sign.client.HsmClientFactory;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;

import com.securosys.simple.sign.client.util.HsmConfigUtil;
import com.securosys.simple.sign.provider.signature.resource.SecurosysUserKeyResourceProviderFactory;

/**
 * Keycloak event listener provider for SecurosysEventListenerProviderFactory.
 */
public class SecurosysEventListenerProviderFactory implements EventListenerProviderFactory {
    private static final Logger logger = Logger.getLogger(SecurosysEventListenerProviderFactory.class);

    public static final String PROVIDER_ID = "securosys-hsm-simple-sign-listener";

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new SecurosysEventListener(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

        // Register for the internal DeleteEvent
        factory.register(event -> {
            if (event instanceof UserModel.UserRemovedEvent) {
                UserModel.UserRemovedEvent deleteEvent = (UserModel.UserRemovedEvent) event;
                handleUserDeletion(deleteEvent);
            }
        });
    }

    private void handleUserDeletion(UserModel.UserRemovedEvent deleteEvent) {
        UserModel user = deleteEvent.getUser();
        KeycloakSession session = deleteEvent.getKeycloakSession();

        // Now you have full access to attributes before they are deleted!
        String keyLabel = user.getFirstAttribute(SecurosysUserKeyResourceProviderFactory.KEY_LABEL);

        if (keyLabel != null && !keyLabel.isEmpty()) {
            try {
                com.securosys.simple.sign.client.config.Config config = HsmConfigUtil.getHsmConfig(session);
                if (config == null) {
                    logger.debugf("[HSM-CLEANUP] Skipping HSM key deletion for user %s because no active Securosys HSM configuration was found",
                            user.getUsername());
                    return;
                }

                HsmClient hsmClient = HsmClientFactory.create(config);
                if (hsmClient == null) {
                    logger.debugf("[HSM-CLEANUP] Skipping HSM key deletion for user %s because HSM client is not available",
                            user.getUsername());
                    return;
                }

                logger.infof("[HSM-CLEANUP] User %s is being deleted. Removing HSM Key: %s",
                        user.getUsername(), keyLabel);

                // Initialize service using the current session context
                hsmClient.deleteKey(keyLabel,null);

                logger.info("[HSM-CLEANUP] HSM Keys are removed successfully.");
            } catch (Exception e) {
                logger.debugf(e, "[HSM-CLEANUP] Skipping HSM key deletion for user %s", user.getUsername());
            }
        }
    }
    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
