package com.auth0;

/**
 * Raised when a refresh-token exchange is attempted after the upstream IdP session ceiling
 * ({@code session_expiry}, see the IPSIE SL1 profile) has already passed.
 * <p>
 * The library is stateless and does not own the session, so it cannot know the ceiling on its own:
 * the application persists {@link Tokens#getSessionExpiresAt()} at login and hands it back via
 * {@link RenewAuthRequest#withSessionExpiresAt(Long)}. When that ceiling has passed,
 * {@link RenewAuthRequest#execute()} throws this exception <em>before</em> calling the token
 * endpoint, so a renewed access token can never outlive the session ceiling. The application should
 * treat this as a "must re-authenticate" outcome rather than retrying the refresh.
 *
 * @see RenewAuthRequest#withSessionExpiresAt(Long)
 * @see Tokens#isSessionExpired()
 */
@SuppressWarnings("WeakerAccess")
public class SessionExpiredException extends IdentityVerificationException {

    static final String SESSION_EXPIRED = "a0.session_expired";

    SessionExpiredException(String message) {
        super(SESSION_EXPIRED, message, null);
    }
}
