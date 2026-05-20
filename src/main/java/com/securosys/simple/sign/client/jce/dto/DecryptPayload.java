package com.securosys.simple.sign.client.jce.dto;

import com.securosys.simple.sign.client.enums.CipherAlgorithm;
import lombok.Data;

@Data
public class DecryptPayload {

	private String encryptedPayload;
	private String decryptKeyName;
	private char[] keyPassword;
	private CipherAlgorithm cipherAlgorithm;
	private String initializationVector;
	private String additionalAuthenticationData;
	private Integer tagLength;
	private Long derivationValue;

}
