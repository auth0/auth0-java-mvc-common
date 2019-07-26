package com.auth0;

/**
 * Represents an error occurred while executing a request against the Auth0 Authentication API
 */
@SuppressWarnings("WeakerAccess")
public class InvalidRequestException extends IdentityVerificationException {
    static final String INVALID_STATE_ERROR = "a0.invalid_state";

    private final String code;
    private final String description;

    InvalidRequestException(String code, String description) {
        super("The request contains an error: " + code);
        this.code = code;
        this.description = description;
    }

    /**
     * Getter for the description of the error.
     *
     * @return the error description if available, null otherwise.
     */
    public String getDescription() {
        return description;
    }

    /**
     * Getter for the code of the error.
     *
     * @return the error code.
     */
    public String getCode() {
        return code;
    }
}
