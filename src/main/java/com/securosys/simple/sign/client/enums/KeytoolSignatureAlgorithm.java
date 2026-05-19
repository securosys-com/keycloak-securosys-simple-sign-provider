
package com.securosys.simple.sign.client.enums;


import com.securosys.simple.sign.client.jce.exception.BusinessException;
import com.securosys.simple.sign.client.jce.exception.BusinessReason;

/**
 * Enumeration of KeytoolSignatureAlgorithm values.
 */
public enum KeytoolSignatureAlgorithm {
	SHA224_WITH_RSA("SHA224withRSA"),
	SHA256_WITH_RSA("SHA256withRSA"),
	SHA384_WITH_RSA("SHA384withRSA"),
	SHA512_WITH_RSA("SHA512withRSA"),
	SHA256_WITH_ECDSA("SHA256withECDSA"),
	SHA384_WITH_ECDSA("SHA384withECDSA"),
	SHA512_WITH_ECDSA("SHA512withECDSA"),
    EDDSA("EdDSA");

	private String algorithm;

	KeytoolSignatureAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public static KeytoolSignatureAlgorithm fromAlgorithm(String algorithm) {
		for (KeytoolSignatureAlgorithm signatureAlgorithm : values()) {
			if (signatureAlgorithm.getAlgorithm().equalsIgnoreCase(algorithm)) {
				return signatureAlgorithm;
			}
		}
		String msg = String.format("algorithm='%s' can not be mapped to SignatureAlgorithm", algorithm);
		throw new BusinessException(msg, BusinessReason.ERROR_INVALID_VALUE_FOR_ENUM);
	}
}
