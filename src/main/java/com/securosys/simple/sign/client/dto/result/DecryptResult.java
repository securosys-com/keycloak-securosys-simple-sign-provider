package com.securosys.simple.sign.client.dto.result;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
/**
 * Data transfer object for DecryptResult.
 */
public class DecryptResult {
    private byte[] payload;
}
