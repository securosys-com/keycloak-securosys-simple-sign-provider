package com.securosys.simple.sign.client.util;

import com.securosys.simple.sign.client.enums.ExtendedKeyUsage;
import com.securosys.simple.sign.client.enums.KeyUsage;
import com.securosys.simple.sign.client.jce.dto.CertificateAttributesDto;
import com.securosys.simple.sign.client.jce.exception.BusinessException;
import com.securosys.simple.sign.client.jce.exception.BusinessReason;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Utility helpers for X.509 certificate parsing.
 */
public final class CertificateUtil {

    private CertificateUtil() {
    }

    public static String getCN(String certificatePem) {
        if (certificatePem == null || certificatePem.isBlank()) {
            return null;
        }

        try {
            X509Certificate certificate = parseCertificate(certificatePem);
            String subject = certificate.getSubjectX500Principal().getName();
            return extractCn(subject);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to extract CN from certificate", e);
        }
    }

    private static X509Certificate parseCertificate(String certificatePem) throws Exception {
        byte[] certificateBytes = decodeCertificate(certificatePem);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
    }

    private static byte[] decodeCertificate(String certificatePem) {
        String pem = certificatePem.trim();
        if (pem.contains("-----BEGIN CERTIFICATE-----")) {
            pem = pem.replaceAll("(?m)^-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("(?m)^-----END CERTIFICATE-----", "")
                    .replaceAll("\s", "");
        }

        try {
            return Base64.getDecoder().decode(pem.getBytes(StandardCharsets.US_ASCII));
        } catch (IllegalArgumentException e) {
            return pem.getBytes(StandardCharsets.UTF_8);
        }
    }

    private static String extractCn(String subject) throws InvalidNameException {
        if (subject == null || subject.isBlank()) {
            return null;
        }
        LdapName ldapName = new LdapName(subject);
        for (Rdn rdn : ldapName.getRdns()) {
            if ("CN".equalsIgnoreCase(rdn.getType())) {
                return rdn.getValue().toString();
            }
        }
        return subject;
    }
    public static String craftKeyUsageString(List<?> usages) {

        if (usages == null || usages.isEmpty()) {
            return "";
        }

        if (usages.get(0) instanceof KeyUsage) {

            List<KeyUsage> mappedKeyUsages = usages.stream()
                    .map(obj -> ((KeyUsage) obj))
                    .collect(Collectors.toList());
            String keyUsage = mappedKeyUsages.stream().map(KeyUsage::getKeyUsage).collect(Collectors.joining(","));
            return "ku:c=" + keyUsage;

        } else if (usages.get(0) instanceof ExtendedKeyUsage) {
            List<ExtendedKeyUsage> mappedKeyUsages = usages.stream()
                    .map(obj -> ((ExtendedKeyUsage) obj))
                    .collect(Collectors.toList());
            String keyUsage = mappedKeyUsages.stream().map(ExtendedKeyUsage::getExtKeyUsage).collect(Collectors.joining(","));
            return "eku:c=" + keyUsage;

        } else if (usages.get(0) instanceof SubjectAlternativeName) {
            // Cast the input list to the correct type
            List<SubjectAlternativeName> sanList = usages.stream()
                    .map(obj -> (SubjectAlternativeName) obj)
                    .collect(Collectors.toList());

            // Map each SubjectAlternativeName object to a "type:value" string
            String sanValues = sanList.stream()
                    .filter(san -> san.getSanType() != null && san.getSanValue() != null)
                    .map(san -> san.getSanType().getSanType() + ":" + san.getSanValue())
                    .collect(Collectors.joining(","));

            return "SAN=" + sanValues;
        }

        return "";
    }
    public static String craftKeytoolDistinguishedName(CertificateAttributesDto attribute) {
        List<String> attributes = new ArrayList<>();
        if (attribute.getCommonName() == null || attribute.getCommonName().isEmpty())
            throw new BusinessException("Could create Certificate Signing request, as the commonName is not specified.", BusinessReason.ERROR_INVALID_CERTIFICATE_REQUEST);

        attributes.add("CN=" + attribute.getCommonName());

        if (attribute.getOrganizationUnitName() != null) {
            attributes.add("OU=" + attribute.getOrganizationUnitName());
        }
        if (attribute.getOrganizationName() != null) {
            attributes.add("O=" + attribute.getOrganizationName());
        }
        if (attribute.getOrganizationIdentifier() != null) {
            attributes.add("2.5.4.97=" + attribute.getOrganizationIdentifier());
        }
        if (attribute.getLocality() != null) {
            attributes.add("L=" + attribute.getLocality());
        }
        if (attribute.getStateOrProvinceName() != null) {
            attributes.add("ST=" + attribute.getStateOrProvinceName());
        }
        if (attribute.getCountry() != null) {
            attributes.add("C=" + attribute.getCountry());
        }
        if (attribute.getEmail() != null) {
            attributes.add("EMAILADDRESS=" + attribute.getEmail());
        }
        if (attribute.getTitle() != null) {
            attributes.add("T=" + attribute.getTitle());
        }
        if (attribute.getSurname() != null) {
            attributes.add("surname=" + attribute.getSurname());
        }
        if (attribute.getGivenName() != null) {
            attributes.add("givenname=" + attribute.getGivenName());
        }
        if (attribute.getInitials() != null) {
            attributes.add("initials=" + attribute.getInitials());
        }
        //if(attribute.getPseudonym() != null) { attributes.add("pseudonym=" + attribute.getPseudonym()); }
        if (attribute.getGenerationQualifier() != null) {
            attributes.add("generation=" + attribute.getGenerationQualifier());
        }

        return attributes.stream().collect(Collectors.joining(", "));
    }
    public static String craftx509BasicConstraint(String constraintKey, String constraintSubKey, boolean constraintValue) {
        if (constraintValue)
            return String.format("%s:%s:%s", constraintKey, constraintSubKey, constraintValue);
        return "";
    }

}
