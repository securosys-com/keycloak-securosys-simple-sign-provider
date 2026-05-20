/**
 * Copyright (c)2026 Securosys SA, authors: Tomasz Madej
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.securosys.simple.sign.provider.signature.resource.record;

/**
 * Represents a request to decrypt a Base64 encrypted payload with the authenticated user's HSM key.
 */
public record DecryptRequest(
        String encryptedPayload,
        String cipherAlgorithm) {
}
