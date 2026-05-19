
package com.securosys.simple.sign.client.util;

import com.securosys.primus.jce.spi0.SpiException;
import com.securosys.primus.tool2.KeyToolX;
import com.securosys.simple.sign.client.enums.KeytoolSignatureAlgorithm;
import com.securosys.simple.sign.client.jce.dto.SynchronousCertificateRequestRequestDto;
import com.securosys.simple.sign.client.jce.exception.BusinessException;
import com.securosys.simple.sign.client.jce.exception.BusinessReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for KeyToolUtil.
 */
public final class KeyToolUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyToolUtil.class);

    private static final String certificateStartdate = "00:00:00";

    // Exception used for data transfer out of the signature operation
    @SuppressWarnings("serial")
    public static class DataTransferException extends RuntimeException {
        private final byte[] data;

        public DataTransferException(final byte[] data) {
            this.data = (data == null ? data : data.clone());
        }

        public byte[] getData() {
            return (data == null ? data : data.clone());
        }

        public static byte[] findData(final Throwable t) {
            for (Throwable f = t; f != null; f = f.getCause()) {
                if (f instanceof DataTransferException) {
                    return ((DataTransferException)f).getData();
                }
            }
            return null;
        }

    }

    private static void setJavaPropertiesForKeyTool(){
        System.setProperty("com.securosys.primus.jce.returnConveniencePrimusCerts", "true");
        System.setProperty("com.securosys.primus.jce.skipPrimusCerts", "true");
        System.setProperty("com.securosys.primus.tool2.keytoolClassName", "com.securosys.primus.kt.Primus");
    }

    private static void addTupleToArrayList(List<String> args, String keyPass, char[] value){
        if(keyPass != null && !keyPass.isEmpty() && value != null){
            args.add(keyPass);
            args.add(new String(value));
        }
    }

    private static void addTupleToArrayList(List<String> args, String key, String value){
        if(key != null && !key.isEmpty() && value != null && !value.isEmpty()){
            args.add(key);
            args.add(value);
        }
    }
    public static File GenerateSyncCertificate(String keyName,
                                               String commonName,
                                               char[] keyPassword,
                                               KeytoolSignatureAlgorithm cipherAlgorithm,
                                               String certificateSigningRequest,
                                               Integer validity,
                                               List<String> extensionArguments){
        return GenerateSyncCertificate(keyName, commonName, keyPassword, cipherAlgorithm, certificateSigningRequest, null,
                null, null, validity, null, extensionArguments);

    }

    public static File GenerateSyncCertificate(String keyName,
                                               String distinguishedName,
                                               char[] keyPassword,
                                               KeytoolSignatureAlgorithm cipherAlgorithm,
                                               String certificateSigningRequest,
                                               String keyUsage,
                                               String extKeyUsage,
                                               String basicConstraint,
                                               Integer validity,
                                               String subjectAlternativeName,
                                               List<String> extensionArguments){
        setJavaPropertiesForKeyTool();
        List<String> args = new ArrayList<>();
        Path csrTmpFilePath = FileUtil.createTemporaryFileWithRndName(keyName, ".csr", certificateSigningRequest.getBytes(StandardCharsets.UTF_8));
        Path crtTmpFilePath = FileUtil.createTemporaryFileWithRndName(keyName, ".crt", null);

        args.add("-gencert");
        addTupleToArrayList(args, "-alias", keyName);
        addTupleToArrayList(args, "-sigalg", cipherAlgorithm.getAlgorithm());
        addTupleToArrayList(args, "-dname", distinguishedName);
        addTupleToArrayList(args, "-infile", csrTmpFilePath.toFile().getPath());
        addTupleToArrayList(args, "-outfile", crtTmpFilePath.toFile().getPath());

        if (validity != null)
            addTupleToArrayList(args, "-validity", Integer.toString(validity));
        if (keyPassword != null)
            addTupleToArrayList(args, "-keypass", keyPassword);

        if(extensionArguments != null && !extensionArguments.isEmpty()) {
            args.addAll(extensionArguments);
        } else {
            if(subjectAlternativeName != null && !subjectAlternativeName.isEmpty())
                addTupleToArrayList(args, "-ext", subjectAlternativeName);
            if(basicConstraint != null && !basicConstraint.isEmpty())
                addTupleToArrayList(args, "-ext", basicConstraint);
            if(keyUsage != null && !keyUsage.isEmpty())
                addTupleToArrayList(args, "-ext", keyUsage);
            if(extKeyUsage != null && !extKeyUsage.isEmpty())
                addTupleToArrayList(args, "-ext", extKeyUsage);
        }

        try{
            LOGGER.debug("Certificate request with args '{}'", args);
            KeyToolX.runInvocation(args.toArray(new String[args.size()]));
            LOGGER.info("Issued a certificate from CSR with key '{}' ", keyName);
            return crtTmpFilePath.toFile();
        } catch (InvocationTargetException e){
            if (e.getCause() != null && e.getCause() instanceof CertificateException){
                String msg = String.format("Key with name '%s' does not have a valid signing-certificate, so key cannot be used for certificate-signing, " +
                        "use the endpoint '/v1/certificate/synchronous/selfsign' first and then perform this request again.", keyName);
                throw new BusinessException(msg, BusinessReason.ERROR_INVALID_CERTIFICATE, e);
            }
            if(e.getCause() != null && e.getCause() instanceof SignatureException){
                SignatureException exp = (SignatureException) e.getCause();
                String msg = "Could not issue certificate: " + exp.getMessage();
                throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
            }
            if(e.getCause() != null && e.getCause() instanceof SpiException){
                SpiException spi = (SpiException) e.getCause();
                if(spi.getMessage().contains("status: PKCS#11: MECHANISM_INVALID;")) {
                    String msg = "Could not issue certificate: The signature Algorithm is not valid for this key type.";
                    throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
                }
            }
            if(e.getCause() != null && e.getCause() instanceof IOException) {
                IOException exp = (IOException) e.getCause();
                String msg = "Could not issue certificate: " + exp.getMessage();
                throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
            }
            String msg = "Could not issue certificate: " + e.getCause().getMessage();
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        } catch (IOException e){
            IOException io = (IOException)e.getCause();
            String msg = "Could not issue certificate: " + io.getMessage();
            throw new BusinessException(msg, BusinessReason.ERROR_IN_SUBSYSTEM, e);
        } catch (Exception e){
            String msg = "Could not issue certificate: " + e.getMessage();
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        } finally {
            if(csrTmpFilePath != null)
                csrTmpFilePath.toFile().delete();
        }
    }
    public static String GenerateCsrSync(SynchronousCertificateRequestRequestDto request,
                                         String distinguishedName,
                                         String keyUsage,
                                         String extendedKeyUsage,
                                         String subjectAlternativeNames) {
        setJavaPropertiesForKeyTool();
        //if(request.getSignatureAlgorithm().getAlgorithm().equals("SHA512withECDSA")){
        //    final Provider provider = Security.getProvider(PrimusProvider.getProviderName());
        //    Security.removeProvider(provider.getName()); // needs to be removed first, otherwise insertProviderAt will not do anything
        //    Security.insertProviderAt(provider, 1);
        //}

        Path file = FileUtil.createTemporaryFileWithRndName(request.getSignKeyName(), ".csr", null);
        List<String> args = new ArrayList<>();

        args.add("-certreq");
        addTupleToArrayList(args, "-alias", request.getSignKeyName());
        addTupleToArrayList(args, "-sigalg", request.getSignatureAlgorithm().getAlgorithm());
        addTupleToArrayList(args, "-dname", distinguishedName);
        addTupleToArrayList(args, "-file", file.toFile().getPath());

        if (keyUsage != null && !keyUsage.isEmpty())
            addTupleToArrayList(args, "-ext", keyUsage);

        if (extendedKeyUsage != null && !extendedKeyUsage.isEmpty())
            addTupleToArrayList(args, "-ext", extendedKeyUsage);

        if(subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty())
            addTupleToArrayList(args, "-ext", subjectAlternativeNames);

        if (request.getKeyPassword() != null)
            addTupleToArrayList(args, "-keypass", request.getKeyPassword());

        try {
            LOGGER.debug("Certificate request with args '{}'", args);
            KeyToolX.runInvocation(args.toArray(new String[args.size()]));
            LOGGER.info("Generated a Certificate Signing Request (CSR) with key '{}' ", request.getSignKeyName());
            return FileUtil.fileToContentString(file.toFile().getPath(), false);
        } catch (InvocationTargetException e){
            if(e.getCause() != null && e.getCause() instanceof SignatureException){
                SignatureException exp = (SignatureException) e.getCause();
                String msg = "Could not create certificate request: " + exp.getMessage();
                throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
            }
            if(e.getCause() != null && e.getCause() instanceof SpiException){
                SpiException spi = (SpiException) e.getCause();
                if(spi.getMessage().contains("status: PKCS#11: MECHANISM_INVALID;")) {
                    String msg = "Could not create certificate request: The signature Algorithm is not valid for this key type.";
                    throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
                }
            }
            if(e.getCause() != null && e.getCause() instanceof IOException) {
                IOException exp = (IOException) e.getCause();
                String msg = "Could not create certificate request: " + exp.getMessage();
                throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
            }
            String msg = "Could not create certificate request.";
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        } catch (IOException e) {
            String msg = "Could not create certificate request.";
            throw new BusinessException(msg, BusinessReason.ERROR_IO, e);
        } catch (Exception e) {
            String msg = "Could not create certificate request.";
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        } finally {
            if (file != null)
                file.toFile().delete();
        }
    }
    public static void GenerateSelfSignedSyncCertificate(String keyName, char[] keyPassword, KeytoolSignatureAlgorithm sigAlg,
                                                     String distinguishedName, String validity, String keyUsage, String extKeyUsage, String basicConstraint, String subjectAlternativeNames) {
        setJavaPropertiesForKeyTool();
        List<String> args = new ArrayList<>();

        args.add("-genkeypair");
        args.add("-justselfsign");
        addTupleToArrayList(args, "-alias", keyName);
        addTupleToArrayList(args, "-sigalg", sigAlg.getAlgorithm());
        addTupleToArrayList(args, "-dname", distinguishedName);
        addTupleToArrayList(args, "-validity", validity);
        addTupleToArrayList(args, "-startdate", certificateStartdate);

        if(keyUsage != null && !keyUsage.isEmpty())
            addTupleToArrayList(args, "-ext", keyUsage);

        if(subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty())
            addTupleToArrayList(args, "-ext", subjectAlternativeNames);

        if(basicConstraint != null && !basicConstraint.isEmpty())
            addTupleToArrayList(args, "-ext", basicConstraint);

        if (extKeyUsage != null && !extKeyUsage.isEmpty())
            addTupleToArrayList(args, "-ext", extKeyUsage);

        if (keyPassword != null)
            addTupleToArrayList(args, "-keypass", keyPassword);

        try {
            LOGGER.debug("Issue SelfSigned Certificate with args '{}'", args);
            KeyToolX.runInvocation(args.toArray(new String[args.size()]));
        } catch (InvocationTargetException e){
            if(e.getCause() != null && e.getCause() instanceof SignatureException){
                SignatureException exp = (SignatureException) e.getCause();
                String msg = "Could not issue certificate: " + exp.getMessage();
                throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
            }
            if(e.getCause() != null && e.getCause() instanceof SpiException){
                SpiException spi = (SpiException) e.getCause();
                if(spi.getMessage().contains("status: PKCS#11: MECHANISM_INVALID;")) {
                    String msg = "Could not issue certificate: The signature Algorithm is not valid for this key type.";
                    throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
                }
            }
            if(e.getCause() != null && e.getCause() instanceof IOException) {
                IOException exp = (IOException) e.getCause();
                String msg = "Could not issue certificate: " + exp.getMessage();
                throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
            }
            String msg = "Could not issue self-signed certificate.";
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        } catch (Exception e) {
            String msg = "Could not issue self-signed certificate.";
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        }
        LOGGER.debug("Self-Sign Certificate request with args '{}'", args);
        LOGGER.info("Issued a Self-Signed Certificate with key '{}' ", keyName);
    }


}