
package com.securosys.simple.sign.client.enums;


import com.securosys.simple.sign.client.jce.exception.BusinessException;
import com.securosys.simple.sign.client.jce.exception.BusinessReason;

/**
 * Utility class for SANType.
 */
public enum SANType {
    DNS("dns"),
    IP("ip"),
    URI("uri"),
    EMAIL("email"),
    OTHERNAME("othername");

    private String sanType;

    SANType(String sanType) { this.sanType = sanType; }

    public static SANType fromInt(int type) {
        switch (type) {
            case 0: return OTHERNAME;
            case 1: return EMAIL;
            case 2: return DNS;
            //case 3: return X400_ADDRESS;
            //case 4: return DIRECTORY_NAME;
            //case 5: return EDI_PARTY_NAME;
            case 6: return URI;
            case 7: return IP;
            //case 8: return RID;
            default: throw new IllegalArgumentException("Invalid SAN type: " + type);
        }
    }

    public String getSanType() { return this.sanType; }

    public static SANType fromSanType(String sanType) {
        for(SANType type : values()) {
            if(type.getSanType().equalsIgnoreCase(sanType)) {
                return type;
            }
        }

        String msg = String.format("sanType='%s' can not be mapped to Subject Alternative Names", sanType);
        throw new BusinessException(msg, BusinessReason.ERROR_INVALID_VALUE_FOR_ENUM);
    }
}
