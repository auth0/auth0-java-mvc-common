package com.auth0;

import com.auth0.jwk.JwkProvider;
import com.auth0.net.client.Auth0HttpClient;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang3.Validate;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Base Auth0 Authenticator class.
 * Allows to easily authenticate using the Auth0 Hosted Login Page.
 */
@SuppressWarnings({ "WeakerAccess", "UnusedReturnValue", "SameParameterValue" })
public class AuthenticationController {

    private final RequestProcessor requestProcessor;

    /**
     * Called from the Builder but also from tests in order to pass the mock.
     */
    @VisibleForTesting
    AuthenticationController(RequestProcessor requestProcessor) {
        this.requestProcessor = requestProcessor;
    }

    @VisibleForTesting
    RequestProcessor getRequestProcessor() {
        return requestProcessor;
    }

    /**
     * Create a new {@link Builder} instance to configure the {@link AuthenticationController} response type and algorithm used on the verification.
     * By default it will request response type 'code' and later perform the Code Exchange, but if the response type is changed to 'token' it will handle
     * the Implicit Grant using the HS256 algorithm with the Client Secret as secret.
     *
     * @param domain       the Auth0 domain
     * @param clientId     the Auth0 application's client id
     * @param clientSecret the Auth0 application's client secret
     * @return a new Builder instance ready to configure
     */
    public static Builder newBuilder(String domain, String clientId, String clientSecret) {
        Validate.notNull(domain, "domain must not be null");
        return new Builder(clientId, clientSecret).withDomain(domain);
    }

    /**
     * Create a new {@link Builder} instance to configure the
     * {@link AuthenticationController} response type and algorithm used on the
     * verification.
     * By default it will request response type 'code' and later perform the Code
     * Exchange, but if the response type is changed to 'token' it will handle
     * the Implicit Grant using the HS256 algorithm with the Client Secret as
     * secret.
     *
     * @param domainResolver the Auth0 domain resolver function
     * @param clientId       the Auth0 application's client id
     * @param clientSecret   the Auth0 application's client secret
     * @return a new Builder instance ready to configure
     */
    public static Builder newBuilder(DomainResolver domainResolver,
            String clientId,
            String clientSecret) {
        Validate.notNull(domainResolver, "domainResolver must not be null");
        return new Builder(clientId, clientSecret).withDomainResolver(domainResolver);
    }

    public static class Builder {
        private static final String RESPONSE_TYPE_CODE = "code";

        private String domain;
        private final String clientId;
        private final String clientSecret;
        private String responseType;
        private JwkProvider jwkProvider;
        private Auth0HttpClient httpClient;
        private Integer clockSkew;
        private Integer authenticationMaxAge;
        private boolean useLegacySameSiteCookie;
        private String organization;
        private String invitation;
        private String cookiePath;
        private DomainResolver domainResolver;

        Builder(String domain, String clientId, String clientSecret) {
            Validate.notNull(domain);
            Validate.notNull(clientId);
            Validate.notNull(clientSecret);

            this.domain = domain;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.responseType = RESPONSE_TYPE_CODE;
            this.useLegacySameSiteCookie = true;
        }

        Builder(String clientId, String clientSecret) {
            if (clientId == null) {
                throw new IllegalArgumentException("clientId cannot be null");
            }
            if (clientSecret == null) {
                throw new IllegalArgumentException("clientSecret cannot be null");
            }

            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.responseType = RESPONSE_TYPE_CODE;
            this.useLegacySameSiteCookie = true;
        }

        /**
         * Sets the Auth0 domain to use.
         * Note: The `domainResolver` must be null when setting the `domain`.
         *
         * @param domain the Auth0 domain to use, a non-null value.
         * @return this same builder instance.
         * @throws IllegalStateException if `domainResolver` is already set.
         */
        public Builder withDomain(String domain) {
            if (this.domainResolver != null) {
                throw new IllegalStateException("Cannot specify both 'domain' and 'domainResolver'.");
            }
            Validate.notNull(domain, "domain must not be null");
            this.domain = domain;
            return this;
        }

        /**
         * Sets the Auth0 domain resolver function to use.
         * Note: The `domain` must be null when setting the `domainResolver`.
         *
         * @param domainResolver the domain resolver function to use, a non-null value.
         * @return this same builder instance.
         * @throws IllegalStateException if `domain` is already set.
         */
        public Builder withDomainResolver(DomainResolver domainResolver) {
            if (this.domain != null) {
                throw new IllegalStateException("Cannot specify both 'domain' and 'domainResolver'.");
            }
            Validate.notNull(domainResolver, "domainResolver must not be null");
            this.domainResolver = domainResolver;
            return this;
        }

        /**
         * Specify that transient authentication-based cookies such as state and nonce are created with the specified
         * {@code Path} cookie attribute.
         *
         * @param cookiePath the path to set on the cookie.
         * @return this builder instance.
         */
        public Builder withCookiePath(String cookiePath) {
            Validate.notNull(cookiePath);
            this.cookiePath = cookiePath;
            return this;
        }

        /**
         * Change the response type to request in the Authorization step. Default value is 'code'.
         *
         * @param responseType the response type to request. Any combination of 'code', 'token' and 'id_token' but 'token id_token' is allowed, using a space as separator.
         * @return this same builder instance.
         */
        public Builder withResponseType(String responseType) {
            Validate.notNull(responseType);
            this.responseType = responseType.trim().toLowerCase();
            return this;
        }

        /**
         * Sets the Jwk Provider that will return the Public Key required to verify the token in case of Implicit Grant flows.
         * This is required if the Auth0 Application is signing the tokens with the RS256 algorithm.
         *
         * @param jwkProvider a valid Jwk provider.
         * @return this same builder instance.
         */
        public Builder withJwkProvider(JwkProvider jwkProvider) {
            Validate.notNull(jwkProvider);
            this.jwkProvider = jwkProvider;
            return this;
        }

        /**
         * Sets a custom {@link Auth0HttpClient} to use for all HTTP requests made by this library
         * (token exchange, PAR, etc.). Use this to configure timeouts, proxies, or other HTTP settings.
         *
         * <p><strong>Note:</strong> When a custom {@code Auth0HttpClient} is provided, the
         * {@link AuthenticationController#setLoggingEnabled(boolean)} and
         * {@link AuthenticationController#doNotSendTelemetry()} settings will have no effect,
         * as those are configured at the HTTP client level. You should configure logging and
         * telemetry directly on the client instance before passing it here.</p>
         *
         * <pre>{@code
         * Auth0HttpClient httpClient = DefaultHttpClient.newBuilder()
         *     .withConnectTimeout(10)
         *     .withReadTimeout(10)
         *     .telemetryEnabled(false)
         *     .withLogging(new LoggingOptions(LoggingOptions.LogLevel.BODY))
         *     .build();
         *
         * AuthenticationController controller = AuthenticationController
         *     .newBuilder(domain, clientId, clientSecret)
         *     .withHttpClient(httpClient)
         *     .build();
         * }</pre>
         *
         * @param httpClient a configured {@link Auth0HttpClient} instance.
         * @return this same builder instance.
         */
        public Builder withHttpClient(Auth0HttpClient httpClient) {
            Validate.notNull(httpClient, "httpClient must not be null");
            this.httpClient = httpClient;
            return this;
        }

        /**
         * Sets the clock-skew or leeway value to use in the ID Token verification. The value must be in seconds.
         * Defaults to 60 seconds.
         *
         * @param clockSkew the clock-skew to use for ID Token verification, in seconds.
         * @return this same builder instance.
         */
        public Builder withClockSkew(Integer clockSkew) {
            Validate.notNull(clockSkew);
            this.clockSkew = clockSkew;
            return this;
        }

        /**
         * Sets the allowable elapsed time in seconds since the last time user was authenticated.
         * By default there is no limit.
         *
         * @param maxAge the max age of the authentication, in seconds.
         * @return this same builder instance.
         */
        public Builder withAuthenticationMaxAge(Integer maxAge) {
            Validate.notNull(maxAge);
            this.authenticationMaxAge = maxAge;
            return this;
        }

        /**
         * Sets whether fallback cookies will be set for clients that do not support SameSite=None cookie attribute.
         * The SameSite Cookie attribute will only be set to "None" if the reponseType includes "id_token".
         * By default this is true.
         * @param useLegacySameSiteCookie whether fallback auth-based cookies should be set.
         * @return this same builder instance.
         */
        public Builder withLegacySameSiteCookie(boolean useLegacySameSiteCookie) {
            this.useLegacySameSiteCookie = useLegacySameSiteCookie;
            return this;
        }

        /**
         * Sets the organization query string parameter value used to login to an organization.
         *
         * @param organization The ID or name of the organization to log the user in to.
         * @return the builder instance.
         */
        public Builder withOrganization(String organization) {
            Validate.notNull(organization);
            this.organization = organization;
            return this;
        }

        /**
         * Sets the invitation query string parameter to join an organization. If using this, you must also specify the
         * organization using {@linkplain Builder#withOrganization(String)}.
         *
         * @param invitation The ID of the invitation to accept. This is available on the URL that is provided when accepting an invitation.
         * @return the builder instance.
         */
        public Builder withInvitation(String invitation) {
            Validate.notNull(invitation);
            this.invitation = invitation;
            return this;
        }

        /**
         * Create a new {@link AuthenticationController} instance that will handle both Code Grant and Implicit Grant flows using either Code Exchange or Token Signature verification.
         *
         * @return a new instance of {@link AuthenticationController}.
         * @throws UnsupportedOperationException if the Implicit Grant is chosen and the environment doesn't support UTF-8 encoding.
         */
        public AuthenticationController build() throws UnsupportedOperationException {
            validateDomainConfiguration();

            DomainProvider domainProvider = domain != null
                    ? new StaticDomainProvider(domain)
                    : new ResolverDomainProvider(domainResolver);

            RequestProcessor.Builder builder = new RequestProcessor.Builder(
                    domainProvider, responseType, clientId, clientSecret)
                    .withClockSkew(clockSkew)
                    .withAuthenticationMaxAge(authenticationMaxAge)
                    .withLegacySameSiteCookie(useLegacySameSiteCookie)
                    .withOrganization(organization)
                    .withInvitation(invitation)
                    .withCookiePath(cookiePath);

            if (jwkProvider != null) {
                builder.withJwkProvider(jwkProvider);
            }
            if (httpClient != null) {
                builder.withHttpClient(httpClient);
            }

            return new AuthenticationController(builder.build());
        }

        private void validateDomainConfiguration() {
            if (domain == null && domainResolver == null) {
                throw new IllegalStateException("Either domain or domainResolver must be provided.");
            }
            if (domain != null && domainResolver != null) {
                throw new IllegalStateException("Cannot specify both domain and domainResolver.");
            }
        }
    }

    /**
     * Whether to enable or not the HTTP Logger for every Request and Response.
     * Enabling this can expose sensitive information.
     *
     * @param enabled whether to enable the HTTP logger or not.
     */
    public void setLoggingEnabled(boolean enabled) {
        requestProcessor.setLoggingEnabled(enabled);
    }

    /**
     * Disable sending the Telemetry header on every request to the Auth0 API
     */
    public void doNotSendTelemetry() {
        requestProcessor.doNotSendTelemetry();
    }

    /**
     * Process a request to obtain a set of {@link Tokens} that represent successful authentication or authorization.
     *
     * This method should be called when processing the callback request to your application. It will validate
     * authentication-related request parameters, handle performing a Code Exchange request if using
     * the "code" response type, and verify the integrity of the ID token (if present).
     *
     * <p><strong>Important:</strong> When using this API, you <strong>must</strong> also use {@link AuthenticationController#buildAuthorizeUrl(HttpServletRequest, HttpServletResponse, String)}
     * when building the {@link AuthorizeUrl} that the user will be redirected to to login. Failure to do so may result
     * in a broken login experience for the user.</p>
     *
     * @param request the received request to process.
     * @param response the received response to process.
     * @return the Tokens obtained after the user authentication.
     * @throws InvalidRequestException       if the error is result of making an invalid authentication request.
     * @throws IdentityVerificationException if an error occurred while verifying the request tokens.
     */
    public Tokens handle(HttpServletRequest request, HttpServletResponse response) throws IdentityVerificationException {
        Validate.notNull(request, "request must not be null");
        Validate.notNull(response, "response must not be null");

        return requestProcessor.process(request, response);
    }

    /**
     * Pre builds an Auth0 Authorize Url with the given redirect URI using a random state and a random nonce if applicable.
     *
     * <p><strong>Important:</strong> When using this API, you <strong>must</strong> also obtain the tokens using the
     * {@link AuthenticationController#handle(HttpServletRequest, HttpServletResponse)} method. Failure to do so will result in a broken login
     * experience for users.</p>
     *
     * @param request     the HTTP request
     * @param response    the HTTP response. Used to store auth-based cookies.
     * @param redirectUri the url to call back with the authentication result.
     * @return the authorize url builder to continue any further parameter customization.
     */
    public AuthorizeUrl buildAuthorizeUrl(HttpServletRequest request, HttpServletResponse response, String redirectUri) {
        Validate.notNull(request, "request must not be null");
        Validate.notNull(response, "response must not be null");
        Validate.notNull(redirectUri, "redirectUri must not be null");

        String state = StorageUtils.secureRandomString();
        String nonce = StorageUtils.secureRandomString();

        return requestProcessor.buildAuthorizeUrl(request, response, redirectUri, state, nonce);
    }

    /**
     * Builds a request to exchange a refresh token for a new set of {@link Tokens}, optionally
     * targeting a specific audience and/or scope. This exposes Auth0's refresh-token grant,
     * enabling Multi-Resource Refresh Token (MRRT) flows where one refresh token can obtain access
     * tokens for multiple APIs.
     *
     * <p>The application supplies the {@code domain} it stored from {@link Tokens#getDomain()} at
     * login. This is required because a refresh can occur outside of an HTTP request, where the
     * domain cannot otherwise be resolved. For applications configured with a fixed domain, the
     * {@link AuthenticationController#renewAuth(String)} overload may be used instead.</p>
     *
     * @param refreshToken the refresh token to exchange.
     * @param domain       the Auth0 domain to target.
     * @return a {@link RenewAuthRequest} to configure and execute.
     */
    public RenewAuthRequest renewAuth(String refreshToken, String domain) {
        Validate.notNull(refreshToken, "refreshToken must not be null");
        Validate.notNull(domain, "domain must not be null");
        return requestProcessor.buildRenewAuthRequest(refreshToken, domain);
    }

    /**
     * Builds a request to exchange a refresh token for a new set of {@link Tokens} using the
     * statically configured domain. See {@link AuthenticationController#renewAuth(String, String)}
     * for details.
     *
     * <p>This overload is only valid when the controller was configured with a fixed domain. When a
     * {@code DomainResolver} is in use, call {@link AuthenticationController#renewAuth(String, String)}
     * with the domain instead.</p>
     *
     * @param refreshToken the refresh token to exchange.
     * @return a {@link RenewAuthRequest} to configure and execute.
     * @throws IllegalStateException if the controller was configured with a {@code DomainResolver}.
     */
    public RenewAuthRequest renewAuth(String refreshToken) {
        Validate.notNull(refreshToken, "refreshToken must not be null");
        return requestProcessor.buildRenewAuthRequest(refreshToken);
    }

    /**
     * Builds a request to exchange a refresh token for a new set of {@link Tokens}, resolving the
     * Auth0 domain from the given request via the configured domain or {@code DomainResolver}.
     * See {@link AuthenticationController#renewAuth(String, String)} for details.
     *
     * <p>This overload works for both a fixed domain and a {@code DomainResolver}, and is convenient
     * when refreshing within an active request. <strong>Note:</strong> a refresh token is bound to
     * the domain it was issued for at login; if the resolver resolves the given request to a
     * different domain, Auth0 will reject the grant. Use this overload only when the request
     * resolves to the same domain as login; otherwise use
     * {@link AuthenticationController#renewAuth(String, String)} with the domain stored from
     * {@link Tokens#getDomain()} at login.</p>
     *
     * @param refreshToken the refresh token to exchange.
     * @param request      the current HTTP request, used to resolve the domain.
     * @return a {@link RenewAuthRequest} to configure and execute.
     */
    public RenewAuthRequest renewAuth(String refreshToken, HttpServletRequest request) {
        Validate.notNull(refreshToken, "refreshToken must not be null");
        Validate.notNull(request, "request must not be null");
        return requestProcessor.buildRenewAuthRequest(refreshToken, request);
    }

    /**
     * Initiates a <a href="https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow">Client-Initiated
     * Backchannel Authentication</a> (CIBA) request. This is the first step of the CIBA flow: it
     * asks Auth0 to authenticate a user out-of-band (on their own device) and returns an
     * {@code auth_req_id} used to poll for the result via {@link #backChannelPoll(String, String)}.
     *
     * <p>The application supplies the {@code domain} to target; store it alongside the returned
     * {@code auth_req_id} so the poll step can target the same domain. For applications configured
     * with a fixed domain, {@link #backChannelAuthorize(String, String, java.util.Map)} may be used
     * instead.</p>
     *
     * <p>The library remains stateless: the application owns the polling loop, honoring the
     * {@code interval} and {@code expires_in} returned by the initiate step.</p>
     *
     * @param scope          the requested scope (e.g. {@code "openid profile"}).
     * @param bindingMessage the human-readable message displayed to the user on their device.
     * @param loginHint      a map identifying the user, serialized to the {@code login_hint} JSON.
     * @param domain         the Auth0 domain to target.
     * @return a {@link BackChannelAuthorizeRequest} to configure and execute.
     */
    public BackChannelAuthorizeRequest backChannelAuthorize(String scope, String bindingMessage, java.util.Map<String, Object> loginHint, String domain) {
        Validate.notNull(scope, "scope must not be null");
        Validate.notNull(bindingMessage, "bindingMessage must not be null");
        Validate.notNull(loginHint, "loginHint must not be null");
        Validate.notNull(domain, "domain must not be null");
        return requestProcessor.buildBackChannelAuthorizeRequest(scope, bindingMessage, loginHint, domain);
    }

    /**
     * Initiates a CIBA backchannel authentication request using the statically configured domain.
     * See {@link #backChannelAuthorize(String, String, java.util.Map, String)} for details.
     *
     * <p>This overload is only valid when the controller was configured with a fixed domain. When a
     * {@code DomainResolver} is in use, call the overload that accepts a domain.</p>
     *
     * @param scope          the requested scope.
     * @param bindingMessage the human-readable message displayed to the user on their device.
     * @param loginHint      a map identifying the user, serialized to the {@code login_hint} JSON.
     * @return a {@link BackChannelAuthorizeRequest} to configure and execute.
     * @throws IllegalStateException if the controller was configured with a {@code DomainResolver}.
     */
    public BackChannelAuthorizeRequest backChannelAuthorize(String scope, String bindingMessage, java.util.Map<String, Object> loginHint) {
        Validate.notNull(scope, "scope must not be null");
        Validate.notNull(bindingMessage, "bindingMessage must not be null");
        Validate.notNull(loginHint, "loginHint must not be null");
        return requestProcessor.buildBackChannelAuthorizeRequest(scope, bindingMessage, loginHint);
    }

    /**
     * Builds a request to poll for the result of a CIBA backchannel authentication request. This is
     * the second step of the CIBA flow: the application calls {@link BackChannelTokenRequest#execute()}
     * repeatedly (no more frequently than the {@code interval} returned by the authorize step) until
     * the user approves (yielding verified {@link Tokens}) or a terminal error occurs.
     *
     * <p>The application supplies the {@code domain} it stored at the authorize step, since polling
     * commonly happens outside the initiating HTTP request. For applications configured with a fixed
     * domain, {@link #backChannelPoll(String)} may be used instead.</p>
     *
     * @param authReqId the {@code auth_req_id} returned from the authorize step.
     * @param domain    the Auth0 domain to target.
     * @return a {@link BackChannelTokenRequest} to execute.
     */
    public BackChannelTokenRequest backChannelPoll(String authReqId, String domain) {
        Validate.notNull(authReqId, "authReqId must not be null");
        Validate.notNull(domain, "domain must not be null");
        return requestProcessor.buildBackChannelTokenRequest(authReqId, domain);
    }

    /**
     * Builds a request to poll for the result of a CIBA backchannel authentication request using the
     * statically configured domain. See {@link #backChannelPoll(String, String)} for details.
     *
     * <p>This overload is only valid when the controller was configured with a fixed domain. When a
     * {@code DomainResolver} is in use, call the overload that accepts a domain.</p>
     *
     * @param authReqId the {@code auth_req_id} returned from the authorize step.
     * @return a {@link BackChannelTokenRequest} to execute.
     * @throws IllegalStateException if the controller was configured with a {@code DomainResolver}.
     */
    public BackChannelTokenRequest backChannelPoll(String authReqId) {
        Validate.notNull(authReqId, "authReqId must not be null");
        return requestProcessor.buildBackChannelTokenRequest(authReqId);
    }

    /**
     * Builds a request to exchange an external {@code subject_token} for a new set of
     * {@link Tokens} via <a href="https://auth0.com/docs/authenticate/custom-token-exchange">Custom
     * Token Exchange</a>, without login semantics. The returned tokens are not verified beyond the
     * exchange itself, making this suitable for obtaining tokens for a downstream API.
     *
     * <p>The application supplies the {@code domain} to target. This is required because a token
     * exchange can occur outside of an HTTP request, where the domain cannot otherwise be resolved.
     * For applications configured with a fixed domain, the
     * {@link AuthenticationController#customTokenExchange(String, String)} overload may be used
     * instead.</p>
     *
     * @param subjectToken     the external token to exchange.
     * @param subjectTokenType the customer-defined URI describing the subject token.
     * @param domain           the Auth0 domain to target.
     * @return a {@link TokenExchangeRequest} to configure and execute.
     */
    public TokenExchangeRequest customTokenExchange(String subjectToken, String subjectTokenType, String domain) {
        Validate.notNull(subjectToken, "subjectToken must not be null");
        Validate.notNull(subjectTokenType, "subjectTokenType must not be null");
        Validate.notNull(domain, "domain must not be null");
        return requestProcessor.buildTokenExchangeRequest(subjectToken, subjectTokenType, domain, false);
    }

    /**
     * Builds a Custom Token Exchange request using the statically configured domain. See
     * {@link AuthenticationController#customTokenExchange(String, String, String)} for details.
     *
     * <p>This overload is only valid when the controller was configured with a fixed domain. When a
     * {@code DomainResolver} is in use, call the overload that accepts a domain.</p>
     *
     * @param subjectToken     the external token to exchange.
     * @param subjectTokenType the customer-defined URI describing the subject token.
     * @return a {@link TokenExchangeRequest} to configure and execute.
     * @throws IllegalStateException if the controller was configured with a {@code DomainResolver}.
     */
    public TokenExchangeRequest customTokenExchange(String subjectToken, String subjectTokenType) {
        Validate.notNull(subjectToken, "subjectToken must not be null");
        Validate.notNull(subjectTokenType, "subjectTokenType must not be null");
        return requestProcessor.buildTokenExchangeRequest(subjectToken, subjectTokenType, false);
    }

    /**
     * Builds a request to exchange an external {@code subject_token} for a login-ready set of
     * {@link Tokens} via <a href="https://auth0.com/docs/authenticate/custom-token-exchange">Custom
     * Token Exchange</a>. Unlike {@link #customTokenExchange(String, String, String)}, the returned
     * ID token is verified (including {@code org_id}/{@code org_name} claims when an organization is
     * configured), yielding tokens suitable for establishing an application session.
     *
     * <p>The application supplies the {@code domain} to target; see
     * {@link #customTokenExchange(String, String, String)} for why.</p>
     *
     * @param subjectToken     the external token to exchange.
     * @param subjectTokenType the customer-defined URI describing the subject token.
     * @param domain           the Auth0 domain to target.
     * @return a {@link TokenExchangeRequest} to configure and execute.
     */
    public TokenExchangeRequest loginWithCustomTokenExchange(String subjectToken, String subjectTokenType, String domain) {
        Validate.notNull(subjectToken, "subjectToken must not be null");
        Validate.notNull(subjectTokenType, "subjectTokenType must not be null");
        Validate.notNull(domain, "domain must not be null");
        return requestProcessor.buildTokenExchangeRequest(subjectToken, subjectTokenType, domain, true);
    }

    /**
     * Builds a login-shaped Custom Token Exchange request using the statically configured domain.
     * See {@link #loginWithCustomTokenExchange(String, String, String)} for details.
     *
     * <p>This overload is only valid when the controller was configured with a fixed domain. When a
     * {@code DomainResolver} is in use, call the overload that accepts a domain.</p>
     *
     * @param subjectToken     the external token to exchange.
     * @param subjectTokenType the customer-defined URI describing the subject token.
     * @return a {@link TokenExchangeRequest} to configure and execute.
     * @throws IllegalStateException if the controller was configured with a {@code DomainResolver}.
     */
    public TokenExchangeRequest loginWithCustomTokenExchange(String subjectToken, String subjectTokenType) {
        Validate.notNull(subjectToken, "subjectToken must not be null");
        Validate.notNull(subjectTokenType, "subjectTokenType must not be null");
        return requestProcessor.buildTokenExchangeRequest(subjectToken, subjectTokenType, true);
    }

}
