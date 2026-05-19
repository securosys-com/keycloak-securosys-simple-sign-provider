package com.securosys.simple.sign.client.jce.dto;

import lombok.Data;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Data
/**
 * Data transfer object for CertificateAttributesDto.
 */
public class CertificateAttributesDto {

    private String commonName;
    private String country;
    private String stateOrProvinceName;
    private String locality;
    private String organizationName;
    private String organizationIdentifier;
    private String organizationUnitName;
    private String email;
    private String title;
    private String surname;
    private String givenName;
    private String initials;
    private String pseudonym;
    private String generationQualifier;
}
