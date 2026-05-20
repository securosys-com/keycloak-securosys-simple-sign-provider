// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.simple.sign.client;


import com.securosys.simple.sign.client.dto.request.CreateKeyDto;
import com.securosys.simple.sign.client.dto.request.CertificateIssueOptions;
import com.securosys.simple.sign.client.dto.result.DecryptResult;
import com.securosys.simple.sign.client.dto.result.SignResult;

import java.security.PublicKey;

/**
 * Common provider-facing operations supported by Securosys HSM clients.
 */
public interface HsmClient {
    HsmKeyAttributes fetchKeyAttributes(String keyLabel, String keyPassword) throws Exception;

    PublicKey getPublicKey(HsmKeyAttributes keyAttributes) throws Exception;

    SignResult createSignature(byte[] payload, String keyName, String password, String algorithm, String signatureType)
            throws Throwable;
    DecryptResult decrypt(String encryptedPayload, String keyName, String password, String cipherAlgorithm)
            throws Exception;
    void createKey(CreateKeyDto createKeyDto) throws Exception;
    boolean checkIfKeyExists(String keyLabel,String password) throws Exception;
    void deleteKey(String keyLabel,String password) throws Exception;
    String getCertFromHsm(String keyLabel, String cname, String caKeyName) throws Exception;
    String doSelfSignedCertificate(String keyLabel, String username) throws Exception;
    String generateCertificateSigningRequest(String keyLabel, CertificateIssueOptions options) throws Exception;
    String importCertificate(String keyLabel, String certificate) throws Exception;
    String issueSignedCertificate(String keyLabel, CertificateIssueOptions options) throws Exception;
}
