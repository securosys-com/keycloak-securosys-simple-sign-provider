
package com.securosys.simple.sign.client.dto.result;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
/**
 * Data transfer object for SignResult.
 */
public class SignResult {
    private byte[] signature;
    private byte[] publicNonce;
}