
package com.securosys.simple.sign.client.jce.dto;

import com.securosys.simple.sign.client.enums.KeytoolSignatureAlgorithm;
import com.securosys.simple.sign.client.enums.ExtendedKeyUsage;
import com.securosys.simple.sign.client.enums.KeyUsage;
import com.securosys.simple.sign.client.util.SubjectAlternativeName;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;

@Data
/**
 * Data transfer object for SynchronousCertificateRequestRequestDto.
 */
public class SynchronousCertificateRequestRequestDto {
    private String signKeyName;

    private char[] keyPassword;

    @NotNull
    private KeytoolSignatureAlgorithm signatureAlgorithm;

    @NotNull
    private CertificateAttributesDto standardCertificateAttributes;

    private List<KeyUsage> keyUsage;

    private List<ExtendedKeyUsage> extendedKeyUsage;

    private List<SubjectAlternativeName> subjectAlternativeNames;

    /*@Valid
    private SignatureDto requestSignature;

    @ArraySchema(schema = @Schema(description = "Signed approvals that are used to synchronously sign with a SKA key. "
            + SwaggerDocDescriptions.SIGNED_APPROVAL, format = "base64"))
    private List<@Base64Encoded String> signedApprovals = new ArrayList<>();*/

}
