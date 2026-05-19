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

package com.securosys.simple.sign.provider.signature.resource.record;

/**
 * Represents a request to sign a payload using a specific key and signer identity.
 * This record is used in the signing endpoint to encapsulate the necessary data for
 * digital signature operations.
 */
public record SignRequest(
        /**
         * The payload to be signed, typically encoded as a Base64 string.
         */
        String payload,
        /**
         * The name of the key to use for signing.
         */
        String keyName,
        /**
         * The common name (CN) of the signer, used for identity verification.
         */
        String signerCn) {
}