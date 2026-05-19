package com.auth0;

import com.auth0.client.LoggingOptions;
import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.exception.IdTokenValidationException;
import com.auth0.exception.PublicKeyProviderException;
import com.auth0.jwt.JWT;
import com.auth0.json.auth.TokenHolder;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.net.client.DefaultHttpClient;
import com.auth0.utils.tokens.IdTokenVerifier;
import com.auth0.utils.tokens.SignatureVerifier;
import org.apache.commons.lang3.Validate;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static com.auth0.InvalidRequestException.*;

/**
 * Main class to handle the Authorize Redirect request.
 * It will try to parse the parameters looking for tokens or an authorization code to perform a Code Exchange against the Auth0 servers.
 */
class RequestProcessor {

    private static final String KEY_STATE = "state";
    private static final String KEY_ERROR = "error";
    private static final String KEY_ERROR_DESCRIPTION = "error_description";
    private static final String KEY_EXPIRES_IN = "expires_in";
    private static final String KEY_ACCESS_TOKEN = "access_token";
    private static final String KEY_ID_TOKEN = "id_token";
    private static final String KEY_TOKEN_TYPE = "token_type";
    private static final String KEY_CODE = "code";
    private static final String KEY_TOKEN = "token";
    private static final String KEY_RESPONSE_MODE = "response_mode";
    private static final String KEY_FORM_POST = "form_post";
    private static final String KEY_MAX_AGE = "max_age";

    private final DomainProvider domainProvider;
    private final String responseType;
    private final String clientId;
    private final String clientSecret;
    private final JwkProvider jwkProvider;

    private final Integer clockSkew;
    private final Integer authenticationMaxAge;
    private final String organization;
    private final String invitation;

    final boolean useLegacySameSiteCookie;
    private final String cookiePath;
    private boolean loggingEnabled = false;
    private boolean telemetryDisabled = false;

    // Cache JwkProviders per domain for MCD support
    private final ConcurrentMap<String, JwkProvider> jwkProviders = new ConcurrentHashMap<>();

    static class Builder {
        private final DomainProvider domainProvider;
        private final String responseType;
        private final String clientId;
        private final String clientSecret;

        private JwkProvider jwkProvider;
        private boolean useLegacySameSiteCookie = true;
        private Integer clockSkew;
        private Integer authenticationMaxAge;
        private String organization;
        private String invitation;
        private String cookiePath;

        public Builder(DomainProvider domainProvider,
                String responseType,
                String clientId,
                String clientSecret) {
            this.domainProvider = domainProvider;
            this.responseType = responseType;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        Builder withJwkProvider(JwkProvider jwkProvider) {
            this.jwkProvider = jwkProvider;
            return this;
        }

        public Builder withClockSkew(Integer clockSkew) {
            this.clockSkew = clockSkew;
            return this;
        }

        public Builder withAuthenticationMaxAge(Integer maxAge) {
            this.authenticationMaxAge = maxAge;
            return this;
        }

        Builder withCookiePath(String cookiePath) {
            this.cookiePath = cookiePath;
            return this;
        }

        Builder withLegacySameSiteCookie(boolean useLegacySameSiteCookie) {
            this.useLegacySameSiteCookie = useLegacySameSiteCookie;
            return this;
        }

        Builder withOrganization(String organization) {
            this.organization = organization;
            return this;
        }

        Builder withInvitation(String invitation) {
            this.invitation = invitation;
            return this;
        }

        RequestProcessor build() {
            return new RequestProcessor(domainProvider, responseType, clientId, clientSecret,
                    jwkProvider, useLegacySameSiteCookie, clockSkew, authenticationMaxAge,
                    organization, invitation, cookiePath);
        }
    }

    private RequestProcessor(DomainProvider domainProvider, String responseType, String clientId,
            String clientSecret, JwkProvider jwkProvider,
            boolean useLegacySameSiteCookie, Integer clockSkew, Integer authenticationMaxAge,
            String organization, String invitation, String cookiePath) {
        this.domainProvider = domainProvider;
        this.responseType = responseType;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.jwkProvider = jwkProvider;
        this.useLegacySameSiteCookie = useLegacySameSiteCookie;
        this.clockSkew = clockSkew;
        this.authenticationMaxAge = authenticationMaxAge;
        this.organization = organization;
        this.invitation = invitation;
        this.cookiePath = cookiePath;
    }

    void setLoggingEnabled(boolean enabled) {
        this.loggingEnabled = enabled;
    }

    void doNotSendTelemetry() {
        this.telemetryDisabled = true;
    }

    AuthAPI createClientForDomain(String domain) {
        DefaultHttpClient.Builder httpBuilder = DefaultHttpClient.newBuilder()
                .telemetryEnabled(!telemetryDisabled);

        if (loggingEnabled) {
            httpBuilder.withLogging(new LoggingOptions(LoggingOptions.LogLevel.BODY));
        }

        return AuthAPI.newBuilder(domain, clientId, clientSecret)
                .withHttpClient(httpBuilder.build())
                .build();
    }

    /**
     * Pre builds an Auth0 Authorize Url with the given redirect URI, state and nonce parameters.
     *
     * @param request     the HTTP request.
     * @param response    the HTTP response, used to set state and nonce as cookies.
     * @param redirectUri the url to call with the authentication result.
     * @param state       a valid state value.
     * @param nonce       the nonce value that will be used if the response type contains 'id_token'. Can be null.
     * @return the authorize url builder to continue any further parameter customization.
     */
    AuthorizeUrl buildAuthorizeUrl(HttpServletRequest request, HttpServletResponse response, String redirectUri,
                                   String state, String nonce) {

        String originDomain = domainProvider.getDomain(request);
        AuthAPI client = createClientForDomain(originDomain);

        AuthorizeUrl creator = new AuthorizeUrl(client, response, redirectUri, responseType)
                .withState(state);

        if (this.organization != null) {
            creator.withOrganization(organization);
        }
        if (this.invitation != null) {
            creator.withInvitation(invitation);
        }
        if (this.cookiePath != null) {
            creator.withCookiePath(this.cookiePath);
        }

        creator.withLegacySameSiteCookie(useLegacySameSiteCookie);
        creator.withOriginDomain(originDomain, clientSecret);

        return getAuthorizeUrl(nonce, creator);
    }

    /**
     * Entrypoint for HTTP request
     * <p>
     * 1). Responsible for validating the request.
     * 2). Exchanging the authorization code received with this HTTP request for Auth0 tokens.
     * 3). Validating the ID Token.
     * 4). Clearing the stored state, nonce and max_age values.
     * 5). Handling success and any failure outcomes.
     *
     * @throws IdentityVerificationException if an error occurred while processing the request
     */
    Tokens process(HttpServletRequest request, HttpServletResponse response) throws IdentityVerificationException {
        assertNoError(request);
        String state = assertValidState(request, response);

        // Extract origin_domain from the HMAC-signed cookie, bound to this transaction's state.
        // If the cookie was tampered with or replayed from a different transaction, returns null.
        String originDomain = TransientCookieStore.getSignedOriginDomain(request, response, state, clientSecret);

        // Fallback if cookie was not set (e.g., single-domain setup without MCD)
        if (originDomain == null) {
            originDomain = domainProvider.getDomain(request);
        }

        // Always derive the issuer from the verified domain — never from a cookie
        String originIssuer = constructIssuer(originDomain);

        Tokens frontChannelTokens = getFrontChannelTokens(request, originDomain, originIssuer);
        List<String> responseTypeList = getResponseType();

        if (responseTypeList.contains(KEY_ID_TOKEN) && frontChannelTokens.getIdToken() == null) {
            throw new InvalidRequestException(MISSING_ID_TOKEN, "ID Token is missing from the response.");
        }
        if (responseTypeList.contains(KEY_TOKEN) && frontChannelTokens.getAccessToken() == null) {
            throw new InvalidRequestException(MISSING_ACCESS_TOKEN, "Access Token is missing from the response.");
        }

        return getVerifiedTokens(request, response, frontChannelTokens, responseTypeList, originDomain, originIssuer);
    }

    static boolean requiresFormPostResponseMode(List<String> responseType) {
        return responseType != null &&
                (responseType.contains(KEY_TOKEN) || responseType.contains(KEY_ID_TOKEN));
    }

    /**
     * Obtains code request tokens (if using Code flow) and validates the ID token.
     * @param request the HTTP request
     * @param frontChannelTokens the tokens obtained from the front channel
     * @param responseTypeList the response types
     * @return a Tokens object that wraps the values obtained from the front-channel and/or the code request response.
     * @throws IdentityVerificationException
     */
    private Tokens getVerifiedTokens(HttpServletRequest request, HttpServletResponse response, Tokens frontChannelTokens, List<String> responseTypeList, String originDomain, String originIssuer)
            throws IdentityVerificationException {

        String authorizationCode = request.getParameter(KEY_CODE);
        Tokens codeExchangeTokens = null;

        String nonce = TransientCookieStore.getNonce(request, response);

        try {
            if (responseTypeList.contains(KEY_ID_TOKEN)) {
                // Implicit/Hybrid flow: must verify front-channel ID Token first.
                verifyIdToken(frontChannelTokens.getIdToken(), originIssuer, originDomain, nonce);
            }
            if (responseTypeList.contains(KEY_CODE)) {
                // Code/Hybrid flow
                String redirectUri = request.getRequestURL().toString();
                codeExchangeTokens = exchangeCodeForTokens(authorizationCode, redirectUri, originDomain);
                if (!responseTypeList.contains(KEY_ID_TOKEN)) {
                    // If we already verified the front-channel token, don't verify it again.
                    String idTokenFromCodeExchange = codeExchangeTokens.getIdToken();
                    if (idTokenFromCodeExchange != null) {
                        verifyIdToken(idTokenFromCodeExchange, originIssuer, originDomain, nonce);
                    }
                }
            }
        } catch (IdTokenValidationException e) {
            throw new IdentityVerificationException(JWT_VERIFICATION_ERROR, "An error occurred while trying to verify the ID Token.", e);
        } catch (Auth0Exception e) {
            throw new IdentityVerificationException(API_ERROR, "An error occurred while exchanging the authorization code.", e);
        }
        // Keep the front-channel ID Token and the code-exchange Access Token.
        return mergeTokens(frontChannelTokens, codeExchangeTokens);
    }

    /**
     * Verifies an ID token using auth0-java v3's IdTokenVerifier.
     * The signature verification strategy is determined by the token's alg header:
     * - RS256: uses JwkProvider (customer-provided or auto-discovered per domain)
     * - HS256: uses client secret
     */
    private void verifyIdToken(String idToken, String issuer, String domain, String nonce) throws IdTokenValidationException {
        SignatureVerifier sigVerifier = buildSignatureVerifier(idToken, domain);

        IdTokenVerifier.Builder verifierBuilder = IdTokenVerifier.init(issuer, clientId, sigVerifier);

        if (clockSkew != null) {
            verifierBuilder.withLeeway(clockSkew);
        }
        if (organization != null) {
            verifierBuilder.withOrganization(organization);
        }

        IdTokenVerifier verifier = verifierBuilder.build();
        verifier.verify(idToken, nonce, authenticationMaxAge);
    }

    /**
     * Builds the appropriate SignatureVerifier based on the token's algorithm header.
     * - If alg is HS256: use client secret
     * - If alg is RS256: use JwkProvider (customer-provided or auto-discovered from domain)
     */
    private SignatureVerifier buildSignatureVerifier(String idToken, String domain) {
        String algorithm = JWT.decode(idToken).getAlgorithm();

        if ("HS256".equals(algorithm)) {
            return SignatureVerifier.forHS256(clientSecret);
        }

        // RS256 (default): use JwkProvider
        JwkProvider provider = getJwkProvider(domain);
        return SignatureVerifier.forRS256(keyId -> {
            try {
                Jwk jwk = provider.get(keyId);
                return (RSAPublicKey) jwk.getPublicKey();
            } catch (JwkException e) {
                throw new PublicKeyProviderException("Failed to get public key for key ID: " + keyId, e);
            }
        });
    }

    /**
     * Gets the JwkProvider for the given domain. If the customer provided one, it is used.
     * Otherwise, a UrlJwkProvider is auto-created and cached per domain.
     */
    private JwkProvider getJwkProvider(String domain) {
        if (jwkProvider != null) {
            return jwkProvider;
        }
        return jwkProviders.computeIfAbsent(domain, d -> new UrlJwkProvider(d));
    }

    List<String> getResponseType() {
        return Arrays.asList(responseType.split(" "));
    }

    private AuthorizeUrl getAuthorizeUrl(String nonce, AuthorizeUrl creator) {
        List<String> responseTypeList = getResponseType();
        if (responseTypeList.contains(KEY_ID_TOKEN) && nonce != null) {
            creator.withNonce(nonce);
        }
        if (requiresFormPostResponseMode(responseTypeList)) {
            creator.withParameter(KEY_RESPONSE_MODE, KEY_FORM_POST);
        }
        if (authenticationMaxAge != null) {
            creator.withParameter(KEY_MAX_AGE, authenticationMaxAge.toString());
        }
        return creator;
    }

    /**
     * Extract the tokens from the request parameters, present when using the Implicit or Hybrid Grant.
     *
     * @param request the request
     * @param originDomain the domain that issued these tokens
     * @param originIssuer the issuer that issued these tokens
     * @return a new instance of Tokens wrapping the values present in the request parameters.
     */
    private Tokens getFrontChannelTokens(HttpServletRequest request, String originDomain, String originIssuer) {
        Long expiresIn = request.getParameter(KEY_EXPIRES_IN) == null ? null : Long.parseLong(request.getParameter(KEY_EXPIRES_IN));
        return new Tokens(request.getParameter(KEY_ACCESS_TOKEN), request.getParameter(KEY_ID_TOKEN), null, request.getParameter(KEY_TOKEN_TYPE), expiresIn, originDomain, originIssuer);
    }

    /**
     * Checks for the presence of an error in the request parameters
     *
     * @param request the request
     * @throws InvalidRequestException if the request contains an error
     */
    private void assertNoError(HttpServletRequest request) throws InvalidRequestException {
        String error = request.getParameter(KEY_ERROR);
        if (error != null) {
            String errorDescription = request.getParameter(KEY_ERROR_DESCRIPTION);
            throw new InvalidRequestException(error, errorDescription);
        }
    }

    /**
     * Checks whether the state received in the request parameters is the same as the one in the state cookie
     * for this request.
     *
     * @param request  the request
     * @param response the response, used to remove the state cookie
     * @throws InvalidRequestException if the request contains a different state from the expected one
     */
    private String assertValidState(HttpServletRequest request, HttpServletResponse response) throws InvalidRequestException {
        String stateFromRequest = request.getParameter(KEY_STATE);

        if (stateFromRequest == null) {
            throw new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one. No state parameter was found on the authorization response.");
        }

        String cookieState = TransientCookieStore.getState(request, response);

        if (cookieState == null) {
            throw new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one. No state cookie found. Check that cookies are not being removed on the server.");
        }

        if (!cookieState.equals(stateFromRequest)) {
            throw new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one.");
        }

        return stateFromRequest;
    }

    /**
     * Calls the Auth0 Authentication API to perform a Code Exchange.
     *
     * @param authorizationCode the code received on the login response.
     * @param redirectUri       the redirect uri used on login request.
     * @return a new instance of {@link Tokens} with the received credentials.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     * @see AuthAPI#exchangeCode(String, String)
     */
    private Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri, String originDomain) throws Auth0Exception {
        AuthAPI client = createClientForDomain(originDomain);
        TokenHolder holder = client
                .exchangeCode(authorizationCode, redirectUri)
                .execute()
                .getBody();
        String originIssuer = constructIssuer(originDomain);
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(), holder.getTokenType(), holder.getExpiresIn(), originDomain, originIssuer);
    }

    /**
     * Used to keep the best version of each token.
     * It will prioritize the ID Token received in the front-channel, and the Access Token received in the code exchange request.
     *
     * @param frontChannelTokens the front-channel obtained tokens.
     * @param codeExchangeTokens the code-exchange obtained tokens.
     * @return a merged version of Tokens using the best tokens when possible.
     */
    private Tokens mergeTokens(Tokens frontChannelTokens, Tokens codeExchangeTokens) {
        if (codeExchangeTokens == null) {
            return frontChannelTokens;
        }

        // Prefer access token from the code exchange
        String accessToken;
        String type;
        Long expiresIn;

        if (codeExchangeTokens.getAccessToken() != null) {
            accessToken = codeExchangeTokens.getAccessToken();
            type = codeExchangeTokens.getType();
            expiresIn = codeExchangeTokens.getExpiresIn();
        } else {
            accessToken = frontChannelTokens.getAccessToken();
            type = frontChannelTokens.getType();
            expiresIn = frontChannelTokens.getExpiresIn();
        }

        // Prefer ID token from the front-channel
        String idToken = frontChannelTokens.getIdToken() != null ? frontChannelTokens.getIdToken() : codeExchangeTokens.getIdToken();

        // Refresh token only available from the code exchange
        String refreshToken = codeExchangeTokens.getRefreshToken();

        // Preserve domain and issuer from either token set (they should be the same)
        String domain = frontChannelTokens.getDomain() != null ? frontChannelTokens.getDomain()
                : codeExchangeTokens.getDomain();
        String issuer = frontChannelTokens.getIssuer() != null ? frontChannelTokens.getIssuer()
                : codeExchangeTokens.getIssuer();

        return new Tokens(accessToken, idToken, refreshToken, type, expiresIn, domain, issuer);
    }

    private String constructIssuer(String domain) {
        if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
            domain = "https://" + domain;
        }
        if (!domain.endsWith("/")) {
            domain = domain + "/";
        }
        return domain;
    }

}