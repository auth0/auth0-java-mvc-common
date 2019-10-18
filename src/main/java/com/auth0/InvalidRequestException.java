package com.auth0;

/**
 * Represents an error occurred while executing a request against the Auth0 Authentication API
 */
@SuppressWarnings("WeakerAccess")
public class InvalidRequestException extends IdentityVerificationException {
    static final String INVALID_STATE_ERROR = "a0.invalid_state";
    static final String MISSING_ID_TOKEN = "a0.missing_id_token";
    static final String MISSING_ACCESS_TOKEN = "a0.missing_access_token";

    private final String code;
    private final String description;

    InvalidRequestException(String code, String description) {
        super("The request contains an error: " + code, description, null);
        this.code = code;
        this.description = description;
    }

    /**
     * Getter for the description of the error.
     *
     * @return the error description if available, null otherwise.
     * @deprecated use {@link #getMessage()}
     */
    @Deprecated
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
