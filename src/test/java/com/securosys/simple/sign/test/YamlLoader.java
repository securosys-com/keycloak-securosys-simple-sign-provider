package com.securosys.simple.sign.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.io.InputStream;

public final class YamlLoader {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(new YAMLFactory());

    private YamlLoader() {
    }

    public static HsmYamlConfig loadConfig(String resourceName) throws IOException {
        try (InputStream inputStream = YamlLoader.class.getClassLoader().getResourceAsStream(resourceName)) {
            if (inputStream == null) {
                throw new IOException("Resource not found: " + resourceName);
            }
            return OBJECT_MAPPER.readValue(inputStream, HsmYamlConfig.class);
        }
    }
}
