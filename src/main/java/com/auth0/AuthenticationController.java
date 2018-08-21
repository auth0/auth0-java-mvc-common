package com.auth0;

import com.auth0.jwk.JwkProvider;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;


/**
 * Base Auth0 Authenticator class.
 * Allows to easily authenticate using the Auth0 Hosted Login Page.
 */
@SuppressWarnings({"WeakerAccess", "UnusedReturnValue", "SameParameterValue"})
public class AuthenticationController {
    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String RESPONSE_TYPE_TOKEN = "token";
    private static final String RESPONSE_TYPE_ID_TOKEN = "id_token";

    private final RequestProcessor requestProcessor;

    private AuthenticationController(RequestProcessor requestProcessor) {
        this.requestProcessor = requestProcessor;
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
         * Create a new {@link AuthenticationController} instance that will handle both Code Grant and Implicit Grant flows using either Code Exchange or Token Signature verification.
         *
         * @return a new instance of {@link AuthenticationController}.
         * @throws UnsupportedOperationException if the Implicit Grant is chosen and the environment doesn't support UTF-8 encoding.
         */
        public AuthenticationController build() throws UnsupportedOperationException {
            return build(new RequestProcessorFactory());
        }

        //Visible for testing
        AuthenticationController build(RequestProcessorFactory factory) throws UnsupportedOperationException {
            responseType = responseType.trim().toLowerCase();
            List<String> types = Arrays.asList(responseType.split(" "));
            if (types.contains(RESPONSE_TYPE_CODE)) {
                return new AuthenticationController(factory.forCodeGrant(domain, clientId, clientSecret, responseType));
            }
            if (types.contains(RESPONSE_TYPE_TOKEN) || types.contains(RESPONSE_TYPE_ID_TOKEN)) {
                RequestProcessor processor;
                if (jwkProvider == null) {
                    try {
                        processor = factory.forImplicitGrant(domain, clientId, clientSecret, responseType);
                    } catch (UnsupportedEncodingException e) {
                        throw new UnsupportedOperationException(e);
                    }
                } else {
                    processor = factory.forImplicitGrant(domain, clientId, clientSecret, responseType, jwkProvider);
                }
                return new AuthenticationController(processor);
            }
            throw new IllegalArgumentException("Response Type must contain any combination of 'code', 'token' or 'id_token'.");
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
     * Processes a request validating the received parameters and performs a Code Exchange or a Token's Signature Verification,
     * depending on the chosen Response Type, to finally obtain a set of {@link Tokens}.
     *
     * @param request the received request to process.
     * @return the Tokens obtained after the user authentication.
     * @throws InvalidRequestException       if the error is result of making an invalid authentication request.
     * @throws IdentityVerificationException if an error occurred while verifying the request tokens.
     */
    public Tokens handle(HttpServletRequest request) throws IdentityVerificationException {
        Validate.notNull(request);

        return requestProcessor.process(request);
    }

    /**
     * Pre builds an Auth0 Authorize Url with the given redirect URI using a random state and a random nonce if applicable.
     *
     * @param request     the caller request. Used to keep the session context.
     * @param redirectUri the url to call back with the authentication result.
     * @return the authorize url builder to continue any further parameter customization.
     */
    public AuthorizeUrl buildAuthorizeUrl(HttpServletRequest request, String redirectUri) {
        Validate.notNull(request);
        Validate.notNull(redirectUri);

        String state = RandomStorage.secureRandomString();
        String nonce = RandomStorage.secureRandomString();

        return requestProcessor.buildAuthorizeUrl(request, redirectUri, state, nonce);
    }

}
