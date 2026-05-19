
package com.securosys.simple.sign.client.enums;

import com.securosys.simple.sign.client.jce.exception.BusinessException;
import com.securosys.simple.sign.client.jce.exception.BusinessReason;

/**
 * Utility class for KeyUsage.
 */
public enum KeyUsage {
    DIGITAL_SIGNATURE("digitalSignature"),
    CONTENT_COMMITMENT("contentCommitment"),
    KEY_ENCIPHERMENT("keyEncipherment"),
    DATA_ENCIPHERMENT("dataEncipherment"),
    KEY_AGREEMENT("keyAgreement"),
    KEY_CERT_SIGN("keyCertSign"),
    CRL_SIGN("cRLSign"),
    ENCIPHER_ONLY("encipherOnly"),
    DECIPHER_ONLY("decipherOnly");

    private String keyUsage;
    KeyUsage(String keyUsage) { this.keyUsage = keyUsage; }
    public String getKeyUsage() {return this.keyUsage; }

    public static KeyUsage fromKeyUsageString(String keyUsage){
        for (KeyUsage usage : values()) {
            if (usage.getKeyUsage().equalsIgnoreCase(keyUsage)) {
                return usage;
            }
        }
        String msg = String.format("keyUsage='%s' can not be mapped to KeyUsage", keyUsage);
        throw new BusinessException(msg, BusinessReason.ERROR_INVALID_VALUE_FOR_ENUM);
    }
}
