
package com.securosys.simple.sign.client.jce.dto;

import com.securosys.simple.sign.client.enums.CopyExtensions;
import com.securosys.simple.sign.client.enums.KeytoolSignatureAlgorithm;
import com.securosys.simple.sign.client.enums.ExtendedKeyUsage;
import com.securosys.simple.sign.client.enums.KeyUsage;
import com.securosys.simple.sign.client.util.SubjectAlternativeName;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;

@Data
/**
 * Data transfer object for SynchronousSignCertificateRequestDto.
 */
public class SynchronousSignCertificateRequestDto {
    @NotEmpty
    private String signKeyName;

    private char[] keyPassword;

    @NotNull
    private KeytoolSignatureAlgorithm signatureAlgorithm;

    private CertificateAttributesDto standardCertificateAttributes;
    
    private String commonName;

    @NotNull
    private int validity;

    private CopyExtensions copyExtensions = CopyExtensions.NO_COPY;

    @NotNull
    private boolean isCertificateAuthority;

    @NotNull
    private String certificateSigningRequest;

    private List<KeyUsage> keyUsage;

    private List<ExtendedKeyUsage> extendedKeyUsage;

    private List<SubjectAlternativeName> subjectAlternativeNames;
}
