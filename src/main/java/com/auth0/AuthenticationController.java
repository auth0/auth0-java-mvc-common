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
        private boolean legacySameSiteCookie;

        Builder(String domain, String clientId, String clientSecret) {
            Validate.notNull(domain);
            Validate.notNull(clientId);
            Validate.notNull(clientSecret);

            this.domain = domain;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.responseType = RESPONSE_TYPE_CODE;
            this.legacySameSiteCookie = true;
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
         * @param legacySameSiteCookie whether fallback auth-based cookies should be set.
         * @return this same builder instance.
         */
        public Builder withLegacySameSiteCookie(boolean legacySameSiteCookie) {
            this.legacySameSiteCookie = legacySameSiteCookie;
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
            RequestProcessor processor = new RequestProcessor(apiClient, responseType, verifyOptions, legacySameSiteCookie);
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
     * Processes a request validating the received parameters and performs a Code Exchange or a Token's Signature Verification,
     * depending on the chosen Response Type, to finally obtain a set of {@link Tokens}.
     *
     * @param request the received request to process.
     * @param response the received response to process.
     * @return the Tokens obtained after the user authentication.
     * @throws InvalidRequestException       if the error is result of making an invalid authentication request.
     * @throws IdentityVerificationException if an error occurred while verifying the request tokens.
     */
    public Tokens handle(HttpServletRequest request, HttpServletResponse response) throws IdentityVerificationException {
        Validate.notNull(request);

        return requestProcessor.process(request, response);
    }

    /**
     * Pre builds an Auth0 Authorize Url with the given redirect URI using a random state and a random nonce if applicable.
     *
     * @param request     the request.
     * @param response    the response. Used to store auth-based cookies.
     * @param redirectUri the url to call back with the authentication result.
     * @return the authorize url builder to continue any further parameter customization.
     */
    public AuthorizeUrl buildAuthorizeUrl(HttpServletRequest request, HttpServletResponse response, String redirectUri) {
        Validate.notNull(response);
        Validate.notNull(redirectUri);

        String state = TransientCookieStore.secureRandomString();
        String nonce = TransientCookieStore.secureRandomString();

        return requestProcessor.buildAuthorizeUrl(response, redirectUri, state, nonce);
    }

}
