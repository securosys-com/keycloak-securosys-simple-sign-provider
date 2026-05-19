
package com.securosys.simple.sign.client.enums;


import com.securosys.simple.sign.client.jce.exception.BusinessException;
import com.securosys.simple.sign.client.jce.exception.BusinessReason;

/**
 * Utility class for ExtendedKeyUsage.
 */
public enum ExtendedKeyUsage {
    ANY_EXTENDED_KEY_USAGE("anyExtendedKeyUsage"),
    SERVER_AUTH("serverAuth"),
    CLIENT_AUTH("clientAuth"),
    CODE_SIGNING("codeSigning"),
    EMAIL_PROTECTION("emailProtection"),
    TIME_STAMPING("timeStamping"),
    OCSP_SIGNING("OCSPSigning");

    private String extKeyUsage;
    ExtendedKeyUsage(String extKeyUsage) { this.extKeyUsage = extKeyUsage; }
    public String getExtKeyUsage() {return this.extKeyUsage; }

    public static ExtendedKeyUsage fromExtKeyUsageString(String extKeyUsage){
        for (ExtendedKeyUsage usage : values()) {
            if (usage.getExtKeyUsage().equalsIgnoreCase(extKeyUsage)) {
                return usage;
            }
        }
        String msg = String.format("extendedKeyUsage='%s' can not be mapped to KeyUsage", extKeyUsage);
        throw new BusinessException(msg, BusinessReason.ERROR_INVALID_VALUE_FOR_ENUM);
    }
}
