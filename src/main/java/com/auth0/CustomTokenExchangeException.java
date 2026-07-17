package com.auth0;

/**
 * Represents a client-side validation error raised before performing a Custom Token Exchange
 * request against the Auth0 Authentication API. These are thrown for malformed inputs (an empty or
 * {@code "Bearer "}-prefixed {@code subject_token}, or a {@code subject_token_type} that is not a
 * valid URI) so the caller fails fast without a network round-trip.
 *
 * @see AuthenticationController#customTokenExchange(String, String)
 * @see AuthenticationController#loginWithCustomTokenExchange(String, String)
 */
@SuppressWarnings("WeakerAccess")
public class CustomTokenExchangeException extends IdentityVerificationException {

    static final String INVALID_TOKEN_FORMAT = "a0.cte_invalid_token_format";
    static final String INVALID_TOKEN_TYPE_URI = "a0.cte_invalid_token_type_uri";

    CustomTokenExchangeException(String code, String message) {
        super(code, message, null);
    }

    /**
     * @return true if the error is due to an empty, whitespace-only, or {@code "Bearer "}-prefixed
     * token value.
     */
    public boolean isInvalidTokenFormat() {
        return INVALID_TOKEN_FORMAT.equals(getCode());
    }

    /**
     * @return true if the error is due to a {@code subject_token_type} value that is not a valid
     * URI.
     */
    public boolean isInvalidTokenTypeUri() {
        return INVALID_TOKEN_TYPE_URI.equals(getCode());
    }
}
