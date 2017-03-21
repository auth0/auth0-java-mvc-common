package com.auth0;

import com.auth0.jwk.JwkProvider;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;


/**
 * Base Auth0 Authenticator class
 */
@SuppressWarnings("WeakerAccess")
public class AuthenticationController {
    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String RESPONSE_TYPE_TOKEN = "token";
    private static final String RESPONSE_TYPE_ID_TOKEN = "id_token";

    private final RequestProcessor requestProcessor;

    private AuthenticationController(RequestProcessor requestProcessor) {
        this.requestProcessor = requestProcessor;
    }

    /**
     * Create a new Builder instance to configure the AuthenticationController response type and algorithm used on the verification.
     * By default it will request Code Grant, but if the response type is changed to 'token' it will handle the Implicit Grant with the
     * algorithm HS256 using as secret the provided Client Secret.
     *
     * @param domain       the Auth0 domain
     * @param clientId     the Auth0 client id
     * @param clientSecret the Auth0 client secret
     * @return a new Builder instance ready to configure
     */
    public static Builder newBuilder(String domain, String clientId, String clientSecret) {
        return new Builder(domain, clientId, clientSecret);
    }

    public static class Builder {
        private final String domain;
        private final String clientId;
        private final String clientSecret;
        private String responseType;
        private JwkProvider jwkProvider;

        Builder(String domain, String clientId, String clientSecret) {
            Validate.notNull(domain);
            Validate.notNull(clientId);
            Validate.notNull(clientSecret);

            this.domain = domain;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.responseType = RESPONSE_TYPE_CODE;
        }

        /**
         * Change the response type to request in the Authorization step. Default value is 'code'.
         *
         * @param responseType the response type to request. Any combination of 'code', 'token' and 'id_token' but 'token id_token' is allowed, using a space as separator.
         * @return this same builder instance.
         */
        public Builder withResponseType(String responseType) {
            Validate.notNull(responseType);
            this.responseType = responseType;
            return this;
        }

        /**
         * Sets the Jwk Provider that will return the Public Key required to verify the token in case of Implicit Grant flows.
         * This is required if the Auth0 Client is signing the tokens with the RS256 algorithm.
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
         * Create a new AuthenticationController instance that will handle both Code Grant and Implicit Grant flows using either Code Exchange or verifying the token's signature.
         *
         * @return a new instance of AuthenticationController.
         * @throws UnsupportedEncodingException if the Implicit Grant is chosen and the environment doesn't support UTF-8 encoding.
         */
        public AuthenticationController build() throws UnsupportedEncodingException {
            return build(new RequestProcessorFactory());
        }

        //Visible for testing
        AuthenticationController build(RequestProcessorFactory factory) throws UnsupportedEncodingException {
            responseType = responseType.trim().toLowerCase();
            List<String> types = Arrays.asList(responseType.split(" "));
            if (types.contains(RESPONSE_TYPE_CODE)) {
                return new AuthenticationController(factory.forCodeGrant(domain, clientId, clientSecret, responseType));
            }
            if (types.contains(RESPONSE_TYPE_TOKEN) && types.contains(RESPONSE_TYPE_ID_TOKEN)) {
                throw new IllegalArgumentException("Response Type 'token id_token' is not supported yet.");
            }
            if (types.contains(RESPONSE_TYPE_TOKEN) || types.contains(RESPONSE_TYPE_ID_TOKEN)) {
                RequestProcessor processor;
                if (jwkProvider == null) {
                    processor = factory.forImplicitGrant(domain, clientId, clientSecret, responseType);
                } else {
                    processor = factory.forImplicitGrant(domain, clientId, clientSecret, responseType, jwkProvider);
                }
                return new AuthenticationController(processor);
            }
            throw new IllegalArgumentException("Response Type must contain any combination of 'code', 'token' or 'id_token'.");
        }
    }


    /**
     * Entrypoint for HTTP request
     * <p>
     * 1). Responsible for validating the request and ensuring the state value in session storage matches the state value passed to this endpoint.
     * 2). Exchanging the authorization code received with this HTTP request for auth0 tokens or extracting and verifying them from the request parameters.
     * 3). Getting the user information associated to the id_token/access_token.
     * 4). Storing the user id into the session storage.
     * 5). Clearing the stored state value.
     * 6). Handling success and any failure outcomes.
     * <p>
     *
     * @param request the received request to process.
     * @return the Tokens obtained after the user authentication.
     * @throws IdentityVerificationException if an error occurred while processing the request
     */
    public Tokens handle(HttpServletRequest request) throws IdentityVerificationException {
        Validate.notNull(request);

        return requestProcessor.process(request);
    }

    /**
     * Builds an Auth0 Authorize Url ready to call with the given parameters.
     *
     * @param request     the caller request. Used to keep the session.
     * @param redirectUri the url to call with the authentication result.
     * @return the authorize url ready to call.
     */
    public String buildAuthorizeUrl(HttpServletRequest request, String redirectUri) {
        String state = RandomStorage.secureRandomString();
        String nonce = RandomStorage.secureRandomString();
        return buildAuthorizeUrl(request, redirectUri, state, nonce);
    }

    /**
     * Builds an Auth0 Authorize Url ready to call with the given parameters.
     *
     * @param request     the caller request. Used to keep the session.
     * @param redirectUri the url to call with the authentication result.
     * @param state       a valid state value.
     * @param nonce       the nonce value that will be used if the response type contains 'id_token'. If this is not the case, it can be null.
     * @return the authorize url ready to call.
     */
    public String buildAuthorizeUrl(HttpServletRequest request, String redirectUri, String state, String nonce) {
        Validate.notNull(request);
        Validate.notNull(redirectUri);
        Validate.notNull(state);

        RandomStorage.setSessionState(request, state);
        if (requestProcessor.getResponseType().contains(RESPONSE_TYPE_ID_TOKEN) && nonce != null) {
            RandomStorage.setSessionNonce(request, nonce);
        }
        return requestProcessor.buildAuthorizeUrl(redirectUri, state, nonce);
    }

}
