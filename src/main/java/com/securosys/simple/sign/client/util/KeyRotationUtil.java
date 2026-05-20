package com.securosys.simple.sign.client.util;

import com.securosys.primus.jce.PrimusPrimitives;
import com.securosys.primus.jce.PrimusRolloverDeriveKey;
import com.securosys.primus.jce.PrimusRolloverKey;
import com.securosys.primus.jce.spi0.Pkcs11StatusIds;
import com.securosys.primus.jce.spi0.SpiException;
import com.securosys.simple.sign.client.dto.request.CreateKeyDto;
import com.securosys.simple.sign.client.jce.PrimusKeyGeneratorFactory;
import com.securosys.simple.sign.client.jce.exception.BusinessException;
import com.securosys.simple.sign.client.jce.exception.BusinessReason;

import javax.crypto.KeyGenerator;

public class KeyRotationUtil {

    public static PrimusRolloverDeriveKey createRolloverKey(String keyName, char[] keyPassword, KeyGenerator keyGenerator) {
        return PrimusRolloverDeriveKey.getOrCreateRolloverKey(keyName, keyPassword, keyGenerator);
    }

    public static PrimusRolloverDeriveKey getSymmetricRolloverKey(String keyName, char[] keyPassword) {
        try {
            PrimusRolloverDeriveKey rolloverKey = PrimusRolloverDeriveKey.getRolloverKey(keyName, keyPassword);
            if(rolloverKey != null) {
                return rolloverKey;
            }
        } catch (Exception e) { // Key is not a rollover key, exception thrown:
            return null;
        }

        return null;
    }

    public static void rotateSymmetricKey(String keyName, String algorithm, char[] keyPassword, int keySize) {
        try {
            PrimusRolloverDeriveKey deriveKey = getOrCreateRolloverKey(keyName, keyPassword, algorithm, keySize);
            if (deriveKey != null) {
                deriveKey.rollover();
                return;
            }
        } catch (SpiException e) {
            if (e.getStatus() == Pkcs11StatusIds.ATTRIBUTE_TYPE_INVALID) {
                String msg = "Key cannot be rotated, missing rollover capability.";
                throw new BusinessException(msg, BusinessReason.ERROR_KEY_ATTRIBUTES_INVALID);
            }
        } catch (IllegalArgumentException e) {
            String msg = "Key cannot be rotated, missing rollover capability.";
            throw new BusinessException(msg, BusinessReason.ERROR_KEY_ATTRIBUTES_INVALID);
        }

        String msg = "Key cannot be rotated, missing rollover capability.";
        throw new BusinessException(msg, BusinessReason.ERROR_KEY_ATTRIBUTES_INVALID);
    }

    public static void rotateAsymmetricKey(String keyName, String algorithm, char[] keyPassword) {
        PrimusRolloverKey key = PrimusRolloverKey.getRolloverKey(keyName, keyPassword);
        if(key != null) {
            key.rollover(PrimusPrimitives.getKeyPairGenerator(algorithm));
        }
        throw new BusinessException("Invalid rollover key.", BusinessReason.ERROR_GENERAL);
    }

    private static PrimusRolloverDeriveKey getOrCreateRolloverKey(String keyName, char[] keyPassword, String algorithm, int keySize) {
        CreateKeyDto createKey = new CreateKeyDto();
        createKey.setLabel(keyName);
        createKey.setPassword(keyPassword);
        createKey.setAlgorithm(algorithm);
        createKey.setKeySize(keySize);
        KeyGenerator primusKeyGenerator = PrimusKeyGeneratorFactory.getKeyGenerator(createKey);
        PrimusRolloverDeriveKey rolloverDeriveKey = PrimusRolloverDeriveKey.getOrCreateRolloverKey(keyName, keyPassword, primusKeyGenerator);
        return rolloverDeriveKey;
    }
}
