package com.auth0;

/**
 * Represents an error returned while polling the Auth0 token endpoint for CIBA (Client-Initiated
 * Backchannel Authentication) login status. The OAuth error codes returned during polling are
 * {@code authorization_pending} (user hasn't approved yet — normal, keep polling), {@code
 * slow_down} (poll less frequently), {@code expired_token} (the auth_req_id expired), and {@code
 * access_denied} (user rejected).
 *
 * <p>The non-terminal cases ({@link #isAuthorizationPending()} and {@link #isSlowDown()}) indicate
 * the caller should sleep and retry. The terminal cases ({@link #isExpiredToken()} and {@link
 * #isAccessDenied()}) indicate the polling loop must stop.
 *
 * @see AuthenticationController#backChannelPoll(String, String)
 */
@SuppressWarnings("WeakerAccess")
public class BackChannelAuthorizationException extends IdentityVerificationException {

    public static final String AUTHORIZATION_PENDING = "authorization_pending";
    public static final String SLOW_DOWN = "slow_down";
    public static final String EXPIRED_TOKEN = "expired_token";
    public static final String ACCESS_DENIED = "access_denied";

    BackChannelAuthorizationException(String code, String message) {
        this(code, message, null);
    }

    BackChannelAuthorizationException(String code, String message, Throwable cause) {
        super(code, message, cause);
    }

    /**
     * @return true if the error is due to the user not yet approving the authentication request.
     * The caller should sleep and retry.
     */
    public boolean isAuthorizationPending() {
        return AUTHORIZATION_PENDING.equals(getCode());
    }

    /**
     * @return true if the polling interval should be increased. The caller should sleep longer and
     * retry.
     */
    public boolean isSlowDown() {
        return SLOW_DOWN.equals(getCode());
    }

    /**
     * @return true if the {@code auth_req_id} has expired. This is a terminal error; the polling
     * loop must stop.
     */
    public boolean isExpiredToken() {
        return EXPIRED_TOKEN.equals(getCode());
    }

    /**
     * @return true if the user rejected the authentication request. This is a terminal error; the
     * polling loop must stop.
     */
    public boolean isAccessDenied() {
        return ACCESS_DENIED.equals(getCode());
    }
}
