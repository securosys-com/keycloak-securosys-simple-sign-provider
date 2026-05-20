package com.securosys.simple.sign.client.enums;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignatureAlgorithmTest {

    @Test
    void shouldMapSupportedTsbRsaAlgorithmsToJceAlgorithms() {
        assertEquals("SHA224withRSA/PSS", SignatureAlgorithm.toJceAlgorithm("SHA224_WITH_RSA_PSS"));
        assertEquals("SHA256withRSA/PSS", SignatureAlgorithm.toJceAlgorithm("SHA256_WITH_RSA_PSS"));
        assertEquals("SHA384withRSA/PSS", SignatureAlgorithm.toJceAlgorithm("SHA384_WITH_RSA_PSS"));
        assertEquals("SHA512withRSA/PSS", SignatureAlgorithm.toJceAlgorithm("SHA512_WITH_RSA_PSS"));
        assertEquals("SHA224withRSA", SignatureAlgorithm.toJceAlgorithm("SHA224_WITH_RSA"));
        assertEquals("SHA256withRSA", SignatureAlgorithm.toJceAlgorithm("SHA256_WITH_RSA"));
        assertEquals("SHA384withRSA", SignatureAlgorithm.toJceAlgorithm("SHA384_WITH_RSA"));
        assertEquals("SHA512withRSA", SignatureAlgorithm.toJceAlgorithm("SHA512_WITH_RSA"));
        assertEquals("SHA1withRSA", SignatureAlgorithm.toJceAlgorithm("SHA1_WITH_RSA"));
        assertEquals("SHA1withRSA/PSS", SignatureAlgorithm.toJceAlgorithm("SHA1_WITH_RSA_PSS"));
    }

    @Test
    void shouldMapSupportedJceRsaAlgorithmsToTsbAlgorithms() {
        assertEquals("SHA224_WITH_RSA_PSS", SignatureAlgorithm.toTsbAlgorithm("SHA224withRSA/PSS"));
        assertEquals("SHA256_WITH_RSA_PSS", SignatureAlgorithm.toTsbAlgorithm("SHA256withRSA/PSS"));
        assertEquals("SHA384_WITH_RSA_PSS", SignatureAlgorithm.toTsbAlgorithm("SHA384withRSA/PSS"));
        assertEquals("SHA512_WITH_RSA_PSS", SignatureAlgorithm.toTsbAlgorithm("SHA512withRSA/PSS"));
        assertEquals("SHA224_WITH_RSA", SignatureAlgorithm.toTsbAlgorithm("SHA224withRSA"));
        assertEquals("SHA256_WITH_RSA", SignatureAlgorithm.toTsbAlgorithm("SHA256withRSA"));
        assertEquals("SHA384_WITH_RSA", SignatureAlgorithm.toTsbAlgorithm("SHA384withRSA"));
        assertEquals("SHA512_WITH_RSA", SignatureAlgorithm.toTsbAlgorithm("SHA512withRSA"));
        assertEquals("SHA1_WITH_RSA", SignatureAlgorithm.toTsbAlgorithm("SHA1withRSA"));
        assertEquals("SHA1_WITH_RSA_PSS", SignatureAlgorithm.toTsbAlgorithm("SHA1withRSA/PSS"));
    }

    @Test
    void shouldDefaultMissingAlgorithmToSha256WithRsa() {
        assertEquals("SHA256withRSA", SignatureAlgorithm.toJceAlgorithm(null));
        assertEquals("SHA256withRSA", SignatureAlgorithm.toJceAlgorithm(""));
        assertEquals("SHA256_WITH_RSA", SignatureAlgorithm.toTsbAlgorithm(null));
        assertEquals("SHA256_WITH_RSA", SignatureAlgorithm.toTsbAlgorithm(""));
    }

    @Test
    void shouldLeaveUnknownAlgorithmUnchanged() {
        assertEquals("EdDSA", SignatureAlgorithm.toJceAlgorithm("EdDSA"));
        assertEquals("EdDSA", SignatureAlgorithm.toTsbAlgorithm("EdDSA"));
    }
}
