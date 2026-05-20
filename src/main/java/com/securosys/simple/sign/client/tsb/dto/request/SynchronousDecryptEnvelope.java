// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.simple.sign.client.tsb.dto.request;

/**
 * Request body for POST /v1/synchronousDecrypt.
 */
public class SynchronousDecryptEnvelope {
    private SynchronousDecryptRequest decryptRequest;

    public SynchronousDecryptEnvelope() {
    }

    public SynchronousDecryptEnvelope(SynchronousDecryptRequest decryptRequest) {
        this.decryptRequest = decryptRequest;
    }

    public SynchronousDecryptRequest getDecryptRequest() {
        return decryptRequest;
    }

    public void setDecryptRequest(SynchronousDecryptRequest decryptRequest) {
        this.decryptRequest = decryptRequest;
    }
}
