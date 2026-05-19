package com.securosys.simple.sign.test;

public class HsmYamlConfig {
    private Hsm hsm;
    private Tsb tsb;

    public Hsm getHsm() {
        return hsm;
    }

    public void setHsm(Hsm hsm) {
        this.hsm = hsm;
    }

    public Tsb getTsb() {
        return tsb;
    }

    public void setTsb(Tsb tsb) {
        this.tsb = tsb;
    }

    public static class Hsm {
        private String host;
        private String port;
        private String user;
        private String setupPassword;
        private String proxyUser;
        private String proxyPassword;
        private String attestationKeyName;
        private String timestampKeyName;
        private String secretPath;
        private String keyLabel;
        private String keyPassword;
        private String algorithm;

        public String getHost() {
            return host;
        }

        public void setHost(String host) {
            this.host = host;
        }

        public String getPort() {
            return port;
        }

        public void setPort(String port) {
            this.port = port;
        }

        public String getUser() {
            return user;
        }

        public void setUser(String user) {
            this.user = user;
        }

        public String getSetupPassword() {
            return setupPassword;
        }

        public void setSetupPassword(String setupPassword) {
            this.setupPassword = setupPassword;
        }

        public String getProxyUser() {
            return proxyUser;
        }

        public void setProxyUser(String proxyUser) {
            this.proxyUser = proxyUser;
        }

        public String getProxyPassword() {
            return proxyPassword;
        }

        public void setProxyPassword(String proxyPassword) {
            this.proxyPassword = proxyPassword;
        }

        public String getAttestationKeyName() {
            return attestationKeyName;
        }

        public void setAttestationKeyName(String attestationKeyName) {
            this.attestationKeyName = attestationKeyName;
        }

        public String getTimestampKeyName() {
            return timestampKeyName;
        }

        public void setTimestampKeyName(String timestampKeyName) {
            this.timestampKeyName = timestampKeyName;
        }

        public String getSecretPath() {
            return secretPath;
        }

        public void setSecretPath(String secretPath) {
            this.secretPath = secretPath;
        }

        public String getKeyLabel() {
            return keyLabel;
        }

        public void setKeyLabel(String keyLabel) {
            this.keyLabel = keyLabel;
        }

        public String getKeyPassword() {
            return keyPassword;
        }

        public void setKeyPassword(String keyPassword) {
            this.keyPassword = keyPassword;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }
    }

    public static class Tsb {
        private String tsbUrl;
        private String auth;
        private String bearerToken;
        private String mtlsP12Path;
        private String mtlsP12Password;
        private String keyOperationApiKey;
        private String keyManagementApiKey;
        private String keyLabel;
        private String keyPassword;
        private String algorithm;

        public String getTsbUrl() {
            return tsbUrl;
        }

        public void setTsbUrl(String tsbUrl) {
            this.tsbUrl = tsbUrl;
        }

        public String getAuth() {
            return auth;
        }

        public void setAuth(String auth) {
            this.auth = auth;
        }

        public String getBearerToken() {
            return bearerToken;
        }

        public void setBearerToken(String bearerToken) {
            this.bearerToken = bearerToken;
        }

        public String getMtlsP12Path() {
            return mtlsP12Path;
        }

        public void setMtlsP12Path(String mtlsP12Path) {
            this.mtlsP12Path = mtlsP12Path;
        }

        public String getMtlsP12Password() {
            return mtlsP12Password;
        }

        public void setMtlsP12Password(String mtlsP12Password) {
            this.mtlsP12Password = mtlsP12Password;
        }

        public String getKeyOperationApiKey() {
            return keyOperationApiKey;
        }

        public void setKeyOperationApiKey(String keyOperationApiKey) {
            this.keyOperationApiKey = keyOperationApiKey;
        }

        public String getKeyManagementApiKey() {
            return keyManagementApiKey;
        }

        public void setKeyManagementApiKey(String keyManagementApiKey) {
            this.keyManagementApiKey = keyManagementApiKey;
        }

        public String getKeyLabel() {
            return keyLabel;
        }

        public void setKeyLabel(String keyLabel) {
            this.keyLabel = keyLabel;
        }

        public String getKeyPassword() {
            return keyPassword;
        }

        public void setKeyPassword(String keyPassword) {
            this.keyPassword = keyPassword;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }
    }
}
