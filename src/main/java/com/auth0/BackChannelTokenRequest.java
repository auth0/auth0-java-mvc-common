package com.auth0;

import com.auth0.exception.Auth0Exception;

/**
 * Class to poll Auth0's token endpoint for the result of a CIBA (Client-Initiated Backchannel
 * Authentication) backchannel authentication request.
 * <p>
 * The library remains stateless: the application owns the polling loop. It must call
 * {@link #execute()} no more frequently than the {@code interval} returned by the initiate step,
 * and handle {@link BackChannelAuthorizationException} to decide whether to keep polling
 * ({@code authorization_pending} / {@code slow_down}) or stop ({@code expired_token} /
 * {@code access_denied}).
 * <p>
 * On success, the returned ID token is verified (signature, issuer, org claims) just like the
 * Custom Token Exchange login path.
 * <p>
 * Obtain an instance via {@link AuthenticationController#backChannelPoll(String, String)}.
 */
@SuppressWarnings({"UnusedReturnValue", "WeakerAccess", "unused"})
public class BackChannelTokenRequest {

    private final RequestProcessor processor;
    private final String authReqId;
    private final String domain;
    private final String issuer;

    BackChannelTokenRequest(RequestProcessor processor, String authReqId, String domain,
                            String issuer) {
        this.processor = processor;
        this.authReqId = authReqId;
        this.domain = domain;
        this.issuer = issuer;
    }

    /**
     * Polls the Auth0 token endpoint for the result of the backchannel authentication request.
     *
     * @return the verified {@link Tokens} once the user has approved the request.
     * @throws BackChannelAuthorizationException while the request is still pending
     *                                           ({@code authorization_pending} / {@code slow_down})
     *                                           or on a terminal poll error ({@code expired_token}
     *                                           / {@code access_denied}).
     * @throws IdentityVerificationException    if the returned ID token fails verification.
     * @throws Auth0Exception                   if the request to the Auth0 server failed.
     */
    public Tokens execute() throws IdentityVerificationException, Auth0Exception {
        return processor.executeBackChannelPoll(authReqId, domain, issuer);
    }
}
