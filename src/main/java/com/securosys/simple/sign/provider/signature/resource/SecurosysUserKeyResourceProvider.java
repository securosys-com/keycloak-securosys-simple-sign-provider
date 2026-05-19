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
 * Resource implementation for SecurosysUserKeyResourceProvider.
 */

package com.securosys.simple.sign.provider.signature.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Resource implementation for SecurosysUserKeyResourceProvider.
 */
public class SecurosysUserKeyResourceProvider implements RealmResourceProvider {

    final KeycloakSession session;

    public SecurosysUserKeyResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new SecurosysUserKeyResource(session);
    }

    @Override
    public void close() {

    }
}