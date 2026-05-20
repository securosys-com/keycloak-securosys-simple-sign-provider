package com.securosys.simple.sign.client.jce.exception;

import com.securosys.primus.jce.spi0.AuthorizationException;
import com.securosys.primus.jce.spi0.StatusIds;
/**
 * Utility class for AuthorizationExceptionHandler.
 */
public final class AuthorizationExceptionHandler {

	/**
	 * Processes an AuthorizationException thrown by the JCE and generates an exception corresponding to the status id
	 * in the AuthorizationException
	 * @param e The AuthorizationException thrown by the JCE
	 */
	public static BusinessException process(AuthorizationException e) {
		if(e.getStatus() == StatusIds.EXTENDED_KEY_ATTRIBUTES_OBJECT_BLOCKED) {
			String msg = "The key operation failed as the key is blocked";
			return new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
		}
		if(e.getStatus() == StatusIds.EXTENDED_KEY_ATTRIBUTES_TOKEN_NOT_FOUND) {
			String msg = "The key operation failed with an authorization error. The provided approvals might be insufficient.";
			return new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
		}
		if(e.getStatus() == StatusIds.EXTENDED_KEY_ATTRIBUTES_PARAMETERS_INVALID){
			String msg = "The key operation failed with an authorization error. The extended Key Attribute Parameters are invalid.";
			return new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
		}
		String msg = String.format("The key operation failed with an authorization error. "
				+ "The status id provided by the JCE is: %s", e.getStatus());
		return new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
	}

}
