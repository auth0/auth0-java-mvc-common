package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;
import com.auth0.net.Telemetry;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Base Auth0 Authenticator class.
 * Allows to easily authenticate using the Auth0 Hosted Login Page.
 */
@SuppressWarnings({"WeakerAccess", "UnusedReturnValue", "SameParameterValue"})
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
        return new Builder(domain, clientId, clientSecret);
    }


    public static class Builder {
        private static final String RESPONSE_TYPE_CODE = "code";

        private final String domain;
        private final String clientId;
        private final String clientSecret;
        private String responseType;
        private JwkProvider jwkProvider;
        private Integer clockSkew;
        private Integer authenticationMaxAge;
        private boolean useLegacySameSiteCookie;

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
         * Create a new {@link AuthenticationController} instance that will handle both Code Grant and Implicit Grant flows using either Code Exchange or Token Signature verification.
         *
         * @return a new instance of {@link AuthenticationController}.
         * @throws UnsupportedOperationException if the Implicit Grant is chosen and the environment doesn't support UTF-8 encoding.
         */
        public AuthenticationController build() throws UnsupportedOperationException {
            AuthAPI apiClient = createAPIClient(domain, clientId, clientSecret);
            setupTelemetry(apiClient);

            final boolean expectedAlgorithmIsExplicitlySetAndAsymmetric = jwkProvider != null;
            final SignatureVerifier signatureVerifier;
            if (expectedAlgorithmIsExplicitlySetAndAsymmetric) {
                signatureVerifier = new AsymmetricSignatureVerifier(jwkProvider);
            } else if (responseType.contains(RESPONSE_TYPE_CODE)) {
                // Old behavior: To maintain backwards-compatibility when
                // no explicit algorithm is set by the user, we
                // must skip ID Token signature check.
                signatureVerifier = new AlgorithmNameVerifier();
            } else {
                signatureVerifier = new SymmetricSignatureVerifier(clientSecret);
            }

            String issuer = getIssuer(domain);
            IdTokenVerifier.Options verifyOptions = createIdTokenVerificationOptions(issuer, clientId, signatureVerifier);
            verifyOptions.setClockSkew(clockSkew);
            verifyOptions.setMaxAge(authenticationMaxAge);
            RequestProcessor processor = new RequestProcessor(apiClient, responseType, verifyOptions, useLegacySameSiteCookie);
            return new AuthenticationController(processor);
        }

        @VisibleForTesting
        IdTokenVerifier.Options createIdTokenVerificationOptions(String issuer, String audience, SignatureVerifier signatureVerifier) {
            return new IdTokenVerifier.Options(issuer, audience, signatureVerifier);
        }

        @VisibleForTesting
        AuthAPI createAPIClient(String domain, String clientId, String clientSecret) {
            return new AuthAPI(domain, clientId, clientSecret);
        }

        @VisibleForTesting
        void setupTelemetry(AuthAPI client) {
            Telemetry telemetry = new Telemetry("auth0-java-mvc-common", obtainPackageVersion());
            client.setTelemetry(telemetry);
        }

        @VisibleForTesting
        String obtainPackageVersion() {
            //Value if taken from jar's manifest file.
            //Call will return null on dev environment (outside of a jar)
            return getClass().getPackage().getImplementationVersion();
        }

        private String getIssuer(String domain) {
            if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
                domain = "https://" + domain;
            }
            if (!domain.endsWith("/")) {
                domain = domain + "/";
            }
            return domain;
        }
    }

    /**
     * Whether to enable or not the HTTP Logger for every Request and Response.
     * Enabling this can expose sensitive information.
     *
     * @param enabled whether to enable the HTTP logger or not.
     */
    public void setLoggingEnabled(boolean enabled) {
        requestProcessor.getClient().setLoggingEnabled(enabled);
    }

    /**
     * Disable sending the Telemetry header on every request to the Auth0 API
     */
    public void doNotSendTelemetry() {
        requestProcessor.getClient().doNotSendTelemetry();
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
     * Process a request to obtain a set of {@link Tokens} that represent successful authentication or authorization.
     *
     * This method should be called when processing the callback request to your application. It will validate
     * authentication-related request parameters, handle performing a Code Exchange request if using
     * the "code" response type, and verify the integrity of the ID token (if present).
     *
     * <p><strong>Important:</strong> When using this API, you <strong>must</strong> also use the {@link AuthenticationController#buildAuthorizeUrl(HttpServletRequest, String)}
     * when building the {@link AuthorizeUrl} that the user will be redirected to to login. Failure to do so may result
     * in a broken login experience for the user.</p>
     *
     * @deprecated This method uses the {@link javax.servlet.http.HttpSession} for auth-based data, and is incompatible
     * with clients that are using the "id_token" or "token" responseType with browsers that enforce SameSite cookie
     * restrictions. This method will be removed in version 2.0.0. Use
     * {@link AuthenticationController#handle(HttpServletRequest, HttpServletResponse)} instead.
     *
     * @param request the received request to process.
     * @return the Tokens obtained after the user authentication.
     * @throws InvalidRequestException       if the error is result of making an invalid authentication request.
     * @throws IdentityVerificationException if an error occurred while verifying the request tokens.
     */
    @Deprecated
    public Tokens handle(HttpServletRequest request) throws IdentityVerificationException {
        Validate.notNull(request, "request must not be null");

        return requestProcessor.process(request, null);
    }

    /**
     * Pre builds an Auth0 Authorize Url with the given redirect URI using a random state and a random nonce if applicable.
     *
     * <p><strong>Important:</strong> When using this API, you <strong>must</strong> also obtain the tokens using the
     * {@link AuthenticationController#handle(HttpServletRequest)} method. Failure to do so may result in a broken login
     * experience for users.</p>
     *
     * @deprecated This method stores data in the {@link javax.servlet.http.HttpSession}, and is incompatible with clients
     * that are using the "id_token" or "token" responseType with browsers that enforce SameSite cookie restrictions.
     * This method will be removed in version 2.0.0. Use
     * {@link AuthenticationController#buildAuthorizeUrl(HttpServletRequest, HttpServletResponse, String)} instead.
     *
     * @param request     the caller request. Used to keep the session context.
     * @param redirectUri the url to call back with the authentication result.
     * @return the authorize url builder to continue any further parameter customization.
     */
    @Deprecated
    public AuthorizeUrl buildAuthorizeUrl(HttpServletRequest request, String redirectUri) {
        Validate.notNull(request, "request must not be null");
        Validate.notNull(redirectUri, "redirectUri must not be null");

        String state = StorageUtils.secureRandomString();
        String nonce = StorageUtils.secureRandomString();

        return requestProcessor.buildAuthorizeUrl(request, null, redirectUri, state, nonce);
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

}
