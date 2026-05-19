package com.securosys.simple.sign.test;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public final class KeycloakProviderContainer {
    private static final Path PROVIDERS_DIR = Path.of("providers");
    private static final Path PROVIDER_DIST_DIR = Path.of("build", "provider-dist");
    private static final String KEYCLOAK_PROVIDERS_DIR = "/opt/keycloak/providers";

    private KeycloakProviderContainer() {
    }

    public static GenericContainer<?> withLocalProviders(GenericContainer<?> container) {
        copyProviderRootFiles(container, PROVIDERS_DIR, KEYCLOAK_PROVIDERS_DIR);
        copyFlatFiles(container, PROVIDERS_DIR.resolve("lib"), KEYCLOAK_PROVIDERS_DIR);
        copyFlatFiles(container, PROVIDER_DIST_DIR.resolve("provider"), KEYCLOAK_PROVIDERS_DIR);
        copyFlatFiles(container, PROVIDER_DIST_DIR.resolve("lib"), KEYCLOAK_PROVIDERS_DIR);

        Path securosysKeys = PROVIDERS_DIR.resolve("securosys-keys");
        if (Files.exists(securosysKeys)) {
            container.withCopyFileToContainer(
                    MountableFile.forHostPath(securosysKeys),
                    KEYCLOAK_PROVIDERS_DIR + "/securosys-keys"
            );
        }
        return container;
    }

    private static void copyFlatFiles(GenericContainer<?> container, Path sourceDir, String targetDir) {
        if (!Files.isDirectory(sourceDir)) {
            return;
        }
        try (Stream<Path> files = Files.list(sourceDir)) {
            files.filter(Files::isRegularFile)
                    .forEach(file -> container.withCopyFileToContainer(
                            MountableFile.forHostPath(file),
                            targetDir + "/" + file.getFileName()
                    ));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to copy provider files from " + sourceDir, e);
        }
    }

    private static void copyProviderRootFiles(GenericContainer<?> container, Path sourceDir, String targetDir) {
        if (!Files.isDirectory(sourceDir)) {
            return;
        }
        try (Stream<Path> files = Files.list(sourceDir)) {
            files.filter(Files::isRegularFile)
                    .filter(KeycloakProviderContainer::isProviderRootFile)
                    .forEach(file -> container.withCopyFileToContainer(
                            MountableFile.forHostPath(file),
                            targetDir + "/" + file.getFileName()
                    ));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to copy provider files from " + sourceDir, e);
        }
    }

    private static boolean isProviderRootFile(Path file) {
        String fileName = file.getFileName().toString();
        return ".secret".equals(fileName)
                || "client.p12".equals(fileName)
                || (fileName.endsWith(".jar")
                && !fileName.endsWith("-all.jar")
                && !fileName.startsWith("keycloak-securosys-hsm-simple-sign-"));
    }
}
