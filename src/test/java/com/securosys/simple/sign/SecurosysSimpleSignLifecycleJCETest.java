package com.securosys.simple.sign;

import com.securosys.simple.sign.test.HsmYamlConfig;
import com.securosys.simple.sign.test.KeycloakProviderContainer;
import com.securosys.simple.sign.test.YamlLoader;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
class SecurosysSimpleSignLifecycleJCETest {
    private static final String REALM = "master";
    private static final String EVENT_LISTENER_ID = "securosys-hsm-simple-sign-listener";
    private static final String USER_KEY_ATTRIBUTE = "securosys_user_key_name";
    private static final String USER_PUBLIC_KEY_ATTRIBUTE = "securosys_public_key";
    private static final Logger LOGGER = LoggerFactory.getLogger("KEYCLOAK_TEST");

    private static String serverUrl;
    private static Keycloak adminClient;

    @Container
    static GenericContainer<?> keycloak = KeycloakProviderContainer.withLocalProviders(
                    new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:latest")))
            .withExposedPorts(8080, 9000)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withEnv("KC_HEALTH_ENABLED", "true")
            .withEnv("KC_LOG_LEVEL", "INFO,com.securosys:DEBUG")
            .withLogConsumer(new Slf4jLogConsumer(LOGGER))
            .waitingFor(
                    Wait.forHttp("/health/live")
                            .forPort(9000)
                            .forStatusCode(200)
                            .withStartupTimeout(Duration.ofMinutes(3))
            )
            .withCommand("start-dev");

    @BeforeAll
    static void setupKeycloak() throws Exception {
        serverUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        adminClient = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(REALM)
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build();

        enableSimpleSignEventListener();
        configureJceHsmKeyProvider();
    }

    @Test
    void shouldGenerateUserKeySignPayloadAndDeleteUser() throws Exception {
        String username = "simple-sign-" + UUID.randomUUID();
        String password = "test-password";

        String userId = createUser(username, password);
        UserRepresentation user = waitForUserHsmAttributes(userId);

        String keyLabel = firstAttribute(user, USER_KEY_ATTRIBUTE);
        String publicKeyBase64 = firstAttribute(user, USER_PUBLIC_KEY_ATTRIBUTE);

        assertEquals(username + "_key", keyLabel);
        assertNotNull(publicKeyBase64);

        String accessToken = getAccessToken(username, password);
        byte[] payload = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String payloadBase64 = Base64.getEncoder().encodeToString(payload);

        Response signResponse = RestAssured.given()
                .contentType("application/json")
                .header("Authorization", "Bearer " + accessToken)
                .body(Map.of("payload", payloadBase64))
                .post(serverUrl + "/realms/" + REALM + "/user_key/sign");

        assertEquals(200, signResponse.statusCode(), signResponse.asString());
        String signatureBase64 = signResponse.jsonPath().getString("signature");
        assertNotNull(signatureBase64);
        assertFalse(signatureBase64.isBlank());

        assertTrue(verifyRsaSignature(payload, Base64.getDecoder().decode(signatureBase64), publicKeyBase64));

        adminClient.realm(REALM).users().delete(userId);
        waitUntilUserIsDeleted(userId);
    }

    private static void enableSimpleSignEventListener() {
        RealmRepresentation realm = adminClient.realm(REALM).toRepresentation();
        List<String> listeners = realm.getEventsListeners() == null
                ? new ArrayList<>()
                : new ArrayList<>(realm.getEventsListeners());

        if (!listeners.contains(EVENT_LISTENER_ID)) {
            listeners.add(EVENT_LISTENER_ID);
        }

        realm.setEventsEnabled(true);
        realm.setAdminEventsEnabled(true);
        realm.setEventsListeners(listeners);
        adminClient.realm(REALM).update(realm);
    }

    private static void configureJceHsmKeyProvider() throws Exception {
        HsmYamlConfig.Hsm hsm = YamlLoader.loadConfig("hsm-config-RS256.yaml").getHsm();

        ComponentRepresentation hsmProvider = new ComponentRepresentation();
        hsmProvider.setName("securosys-hsm-jce");
        hsmProvider.setProviderId("securosys-hsm-jce");
        hsmProvider.setProviderType("org.keycloak.keys.KeyProvider");

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.put("priority", Collections.singletonList("10000"));
        config.put("connectionTimeout", Collections.singletonList("10000"));
        config.put("enabled", Collections.singletonList("true"));
        config.put("active", Collections.singletonList("true"));
        config.put("hsmHost", Collections.singletonList(hsm.getHost()));
        config.put("hsmPort", Collections.singletonList(hsm.getPort()));
        config.put("hsmUser", Collections.singletonList(hsm.getUser()));
        config.put("hsmSetupPassword", Collections.singletonList(hsm.getSetupPassword()));
        config.put("hsmProxyUser", Collections.singletonList(hsm.getProxyUser()));
        config.put("hsmProxyPassword", Collections.singletonList(hsm.getProxyPassword()));
        config.put("attestationKeyName", Collections.singletonList(hsm.getAttestationKeyName()));
        config.put("timestampKeyName", Collections.singletonList(hsm.getTimestampKeyName()));
        config.put("timestampSignatureAlgorithm", Collections.singletonList("SHA256withRSA"));
        config.put("hsmSecretPath", Collections.singletonList(hsm.getSecretPath()));
        config.put("keyLabel", Collections.singletonList(hsm.getKeyLabel()));
        config.put("keyPassword", Collections.singletonList(hsm.getKeyPassword()));
        config.put("algorithm", Collections.singletonList("RS256"));
        hsmProvider.setConfig(config);

        jakarta.ws.rs.core.Response response = adminClient.realm(REALM).components().add(hsmProvider);
        if (response.getStatus() != 201) {
            throw new IllegalStateException("Failed to add HSM provider: " + response.readEntity(String.class)
                    + "\nKeycloak log tail:\n" + tail(keycloak.getLogs(), 120));
        }
    }

    private static String createUser(String username, String password) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);

        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEnabled(true);
        user.setCredentials(Collections.singletonList(credential));

        jakarta.ws.rs.core.Response response = adminClient.realm(REALM).users().create(user);
        if (response.getStatus() != 201) {
            throw new IllegalStateException("Failed to create user: " + response.readEntity(String.class));
        }

        String path = response.getLocation().getPath();
        return path.substring(path.lastIndexOf('/') + 1);
    }

    private static UserRepresentation waitForUserHsmAttributes(String userId) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        UserRepresentation user = null;

        while (System.nanoTime() < deadline) {
            user = adminClient.realm(REALM).users().get(userId).toRepresentation();
            if (firstAttribute(user, USER_KEY_ATTRIBUTE) != null && firstAttribute(user, USER_PUBLIC_KEY_ATTRIBUTE) != null) {
                return user;
            }
            Thread.sleep(1000);
        }

        throw new AssertionError("Timed out waiting for HSM user attributes. Last user representation: " + user);
    }

    private static String getAccessToken(String username, String password) {
        Response tokenResponse = RestAssured.given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "password")
                .formParam("client_id", "admin-cli")
                .formParam("username", username)
                .formParam("password", password)
                .post(serverUrl + "/realms/" + REALM + "/protocol/openid-connect/token");

        assertEquals(200, tokenResponse.statusCode(), tokenResponse.asString());
        String accessToken = tokenResponse.jsonPath().getString("access_token");
        assertNotNull(accessToken);
        return accessToken;
    }

    private static boolean verifyRsaSignature(byte[] payload, byte[] signature, String publicKeyBase64) throws Exception {
        byte[] encodedPublicKey = Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedPublicKey));

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(payload);
        return verifier.verify(signature);
    }

    private static void waitUntilUserIsDeleted(String userId) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (System.nanoTime() < deadline) {
            try {
                adminClient.realm(REALM).users().get(userId).toRepresentation();
            } catch (jakarta.ws.rs.NotFoundException e) {
                return;
            }
            Thread.sleep(500);
        }
        throw new AssertionError("Timed out waiting for user deletion: " + userId);
    }

    private static String firstAttribute(UserRepresentation user, String attributeName) {
        if (user.getAttributes() == null || user.getAttributes().get(attributeName) == null
                || user.getAttributes().get(attributeName).isEmpty()) {
            return null;
        }
        return user.getAttributes().get(attributeName).get(0);
    }

    private static String tail(String value, int maxLines) {
        String[] lines = value.split("\\R");
        int start = Math.max(0, lines.length - maxLines);
        return String.join(System.lineSeparator(), java.util.Arrays.copyOfRange(lines, start, lines.length));
    }
}
