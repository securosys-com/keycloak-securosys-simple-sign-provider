package com.securosys.simple.sign.provider.signature.resource.record;

import java.util.List;

public record CertificateRequest(
        Boolean issueCertificate,
        String caKeyName,
        String commonName,
        String country,
        String stateOrProvinceName,
        String locality,
        String organizationName,
        String organizationIdentifier,
        String organizationUnitName,
        String email,
        String title,
        String surname,
        String givenName,
        String initials,
        String pseudonym,
        String generationQualifier,
        Integer validity,
        String signatureAlgorithm,
        List<String> keyUsage,
        List<String> extendedKeyUsage,
        Boolean certificateAuthority) {
}
