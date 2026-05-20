// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.simple.sign.client.tsb.dto.response;

/**
 * Response body for POST /v1/synchronousDecrypt.
 */
public class SynchronousDecryptResponse {
    private String payload;

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }
}
