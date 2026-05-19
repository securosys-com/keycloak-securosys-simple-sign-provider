package com.securosys.simple.sign.client.util;

import com.securosys.simple.sign.client.config.Config;
import com.securosys.simple.sign.client.config.JceConfig;
import com.securosys.simple.sign.client.config.TsbConfig;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Comparator;
import java.util.Optional;

/**
 * Utility class for resolving the active Securosys HSM configuration.
 */
public final class HsmConfigUtil {
    public static final String JCE_PROVIDER = "securosys-hsm-jce";
    public static final String TSB_PROVIDER = "securosys-hsm-tsb";

    private static final String DEFAULT_CONNECTION_TIMEOUT = "10000";

    private HsmConfigUtil() {
    }

    public static Config getHsmConfig(KeycloakSession session) {
        Optional<ComponentModel> model = session.getContext().getRealm().getComponentsStream(
                        session.getContext().getRealm().getId(),
                        KeyProvider.class.getName()
                )
                .filter(HsmConfigUtil::isSecurosysProvider)
                .filter(c -> Boolean.parseBoolean(c.get(Attributes.ENABLED_KEY)))
                .max(Comparator.comparingLong(HsmConfigUtil::getPriority));

        return model.map(HsmConfigUtil::toConfig).orElse(null);
    }

    public static boolean isSecurosysProvider(ComponentModel model) {
        return JCE_PROVIDER.equals(model.getProviderId())
                || TSB_PROVIDER.equals(model.getProviderId());
    }

    public static Config toConfig(ComponentModel model) {
        if (JCE_PROVIDER.equals(model.getProviderId())) {
            return toJceConfig(model);
        }
        if (TSB_PROVIDER.equals(model.getProviderId())) {
            return toTsbConfig(model);
        }
        return null;
    }

    private static JceConfig toJceConfig(ComponentModel model) {
        JceConfig config = new JceConfig();
        mapModelConfig(model, config);
        if (config.getConnectionTimeout() == null) {
            config.setConnectionTimeout(DEFAULT_CONNECTION_TIMEOUT);
        }
        return config;
    }

    private static TsbConfig toTsbConfig(ComponentModel model) {
        TsbConfig config = TsbConfig.builder().build();
        mapModelConfig(model, config);
        return config;
    }

    private static void mapModelConfig(ComponentModel model, Config config) {
        Map<String, Field> fields = getFieldsByName(config.getClass());
        for (Map.Entry<String, List<String>> entry : model.getConfig().entrySet()) {
            String value = firstValue(entry.getValue());
            if (value == null) {
                continue;
            }
            Field field = fields.get(normalize(entry.getKey()));
            if (field == null) {
                field = fields.get(normalize(removeHsmPrefix(entry.getKey())));
            }
            if (field == null) {
                field = fields.get(normalize(removeMethodSuffix(entry.getKey())));
            }
            if (field != null) {
                setField(config, field, value);
            }
        }
    }

    private static Map<String, Field> getFieldsByName(Class<?> type) {
        Map<String, Field> fields = new HashMap<>();
        Class<?> current = type;
        while (current != null) {
            for (Field field : current.getDeclaredFields()) {
                fields.put(normalize(field.getName()), field);
            }
            current = current.getSuperclass();
        }
        return fields;
    }

    private static String firstValue(List<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.get(0);
    }

    private static String removeHsmPrefix(String key) {
        if (key.length() > 3 && key.startsWith("hsm") && Character.isUpperCase(key.charAt(3))) {
            return Character.toLowerCase(key.charAt(3)) + key.substring(4);
        }
        return key;
    }

    private static String removeMethodSuffix(String key) {
        if (key.endsWith("Method")) {
            return key.substring(0, key.length() - "Method".length());
        }
        return key;
    }

    private static String normalize(String key) {
        return key.toLowerCase();
    }

    private static void setField(Config config, Field field, String value) {
        try {
            field.setAccessible(true);
            field.set(config, value);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Failed to map HSM config field " + field.getName(), e);
        }
    }

    private static long getPriority(ComponentModel model) {
        try {
            return Long.parseLong(model.get(Attributes.PRIORITY_KEY, "0"));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
