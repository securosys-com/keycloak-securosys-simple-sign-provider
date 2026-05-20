// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.simple.sign.client.tsb.dto.request;

/**
 * Nested decryptRequest payload for POST /v1/synchronousDecrypt.
 */
public class SynchronousDecryptRequest {
    private String encryptedPayload;
    private String decryptKeyName;
    private String keyPassword;
    private String cipherAlgorithm;

    public String getEncryptedPayload() {
        return encryptedPayload;
    }

    public void setEncryptedPayload(String encryptedPayload) {
        this.encryptedPayload = encryptedPayload;
    }

    public String getDecryptKeyName() {
        return decryptKeyName;
    }

    public void setDecryptKeyName(String decryptKeyName) {
        this.decryptKeyName = decryptKeyName;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    public void setCipherAlgorithm(String cipherAlgorithm) {
        this.cipherAlgorithm = cipherAlgorithm;
    }
}
