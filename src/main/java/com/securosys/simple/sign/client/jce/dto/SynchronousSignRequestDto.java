
package com.securosys.simple.sign.client.jce.dto;

import com.securosys.simple.sign.client.enums.PayloadType;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
/**
 * Data transfer object for SynchronousSignRequestDto.
 */
public class SynchronousSignRequestDto {

	@NotEmpty
	private String payload;

	private PayloadType payloadType = PayloadType.UNSPECIFIED;

	@NotEmpty
	private String signKeyName;

	private String signKeyObject;

	private char[] keyPassword;

	private String metaData;

	private String metaDataSignature;

	private String signatureAlgorithm;

	private String signatureType;

	private String context;

	private String auxiliaryRandomData;

	private String taprootTweakData;

	private String merkleRootData;

	private List<String> signedApprovals = new ArrayList<>();

}
