// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.simple.sign.client;

import com.securosys.simple.sign.client.jce.JceClient;
import com.securosys.simple.sign.client.tsb.TsbClient;
import com.securosys.simple.sign.client.config.Config;
import com.securosys.simple.sign.client.config.JceConfig;
import com.securosys.simple.sign.client.config.TsbConfig;

/**
 * Creates the correct HSM client implementation for a configuration type.
 */
public final class HsmClientFactory {
    private HsmClientFactory() {
    }

    public static HsmClient create(Config config) throws Exception {
        if (config == null) {
            throw new IllegalArgumentException("HSM configuration was null");
        }
        if (config instanceof JceConfig) {
            return new JceClient((JceConfig) config);
        }
        if (config instanceof TsbConfig) {
            return new TsbClient((TsbConfig) config);
        }
        throw new IllegalArgumentException("Unsupported HSM configuration type: " + config.getClass().getName());
    }
}
