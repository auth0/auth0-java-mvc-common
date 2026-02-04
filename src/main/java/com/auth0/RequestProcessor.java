package com.auth0;

import com.auth0.client.HttpOptions;
import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.Telemetry;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.auth0.InvalidRequestException.*;

/**
 * Main class to handle the Authorize Redirect request.
 * It will try to parse the parameters looking for tokens or an authorization
 * code to perform a Code Exchange against the Auth0 servers.
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

    // Visible for testing

    private final DomainProvider domainProvider;
    private final String responseType;
    private final String clientId;
    private final String clientSecret;
    private final HttpOptions httpOptions;
    private SignatureVerifier signatureVerifier;

    // Configuration values passed from Builder for creating per-request
    // verification options
    private final Integer clockSkew;
    private final Integer authenticationMaxAge;
    private final String organization;
    private final String invitation;

    final boolean useLegacySameSiteCookie;
    private AuthAPI client;
    private final IdTokenVerifier tokenVerifier;
    private final String cookiePath;
    private boolean loggingEnabled = false;
    private boolean telemetryDisabled = false;

    static class Builder {
        private final DomainProvider domainProvider;
        private final String responseType;
        private final String clientId;
        private final String clientSecret;
        private final HttpOptions httpOptions;
        private final SignatureVerifier signatureVerifier;

        private boolean useLegacySameSiteCookie = true;
        private Integer clockSkew;
        private Integer authenticationMaxAge;
        private String organization;
        private String invitation;
        private String cookiePath;

        public Builder(DomainProvider domainProvider,
                String responseType,
                String clientId,
                String clientSecret,
                HttpOptions httpOptions,
                SignatureVerifier signatureVerifier) {
            this.domainProvider = domainProvider;
            this.responseType = responseType;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.httpOptions = httpOptions;
            this.signatureVerifier = signatureVerifier;
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

            return new RequestProcessor(domainProvider, responseType, clientId, clientSecret, httpOptions,
                    signatureVerifier, new IdTokenVerifier(),
                    useLegacySameSiteCookie, clockSkew, authenticationMaxAge, organization, invitation, cookiePath);
        }
    }

    private RequestProcessor(DomainProvider domainProvider, String responseType, String clientId, String clientSecret,
            HttpOptions httpOptions, SignatureVerifier signatureVerifier, IdTokenVerifier tokenVerifier,
            boolean useLegacySameSiteCookie, Integer clockSkew, Integer authenticationMaxAge,
            String organization, String invitation, String cookiePath) {
        this.domainProvider = domainProvider;
        this.responseType = responseType;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.httpOptions = httpOptions;
        this.signatureVerifier = signatureVerifier;
        this.tokenVerifier = tokenVerifier;
        this.useLegacySameSiteCookie = useLegacySameSiteCookie;

        // Store individual configuration values instead of pre-built verifyOptions
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

    /**
     * Getter for the AuthAPI client instance.
     * Used to customize options such as Telemetry and Logging.
     *
     * @return the AuthAPI client.
     */
    AuthAPI getClient() {
        return client;
    }

    AuthAPI createClientForDomain(String domain) {
        final AuthAPI client;

        if (httpOptions != null) {
            client = new AuthAPI(domain, clientId, clientSecret, httpOptions);
        } else {
            client = new AuthAPI(domain, clientId, clientSecret);
        }

        // Apply deferred settings
        client.setLoggingEnabled(loggingEnabled);
        if (telemetryDisabled) {
            client.doNotSendTelemetry();
        } else {
            setupTelemetry(client);
        }

        System.out.println("Created dynamic AuthAPI for domain: " + domain + " " + clientId);
        return client;
    }

    void setupTelemetry(AuthAPI client) {
        Telemetry telemetry = new Telemetry("auth0-java-mvc-common", obtainPackageVersion());
        client.setTelemetry(telemetry);
    }

    @VisibleForTesting
    String obtainPackageVersion() {
        return getClass().getPackage().getImplementationVersion();
    }

    /**
     * Pre builds an Auth0 Authorize Url with the given redirect URI, state and
     * nonce parameters.
     *
     * @param request     the request, used to store state and nonce in the Session
     * @param response    the response, used to set state and nonce as cookies. If
     *                    null, session will be used instead.
     * @param redirectUri the url to call with the authentication result.
     * @param state       a valid state value.
     * @param nonce       the nonce value that will be used if the response type
     *                    contains 'id_token'. Can be null.
     * @return the authorize url builder to continue any further parameter
     *         customization.
     */
    AuthorizeUrl buildAuthorizeUrl(HttpServletRequest request, HttpServletResponse response, String redirectUri,
            String state, String nonce) {

        String originDomain = domainProvider.getDomain(request);
        AuthAPI client = createClientForDomain(originDomain);

        AuthorizeUrl creator = new AuthorizeUrl(client, request, response, redirectUri, responseType)
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

        // null response means state and nonce will be stored in session, so legacy
        // cookie flag does not apply
        if (response != null) {
            creator.withLegacySameSiteCookie(useLegacySameSiteCookie);
        }

        boolean isSecure = request.isSecure();

        TransientCookieStore.storeOriginData(
                response,
                originDomain,
                SameSite.LAX,
                constructIssuer(originDomain),
                cookiePath,
                isSecure);

        TransientCookieStore.storeOriginData(response, originDomain, SameSite.LAX, constructIssuer(originDomain), cookiePath,
                isSecure);

        return getAuthorizeUrl(nonce, creator);
    }

    /**
     * Entrypoint for HTTP request
     * <p>
     * 1). Responsible for validating the request.
     * 2). Exchanging the authorization code received with this HTTP request for
     * Auth0 tokens.
     * 3). Validating the ID Token.
     * 4). Clearing the stored state, nonce and max_age values.
     * 5). Handling success and any failure outcomes.
     *
     * @throws IdentityVerificationException if an error occurred while processing
     *                                       the request
     */
    Tokens process(HttpServletRequest request, HttpServletResponse response) throws IdentityVerificationException {
        assertNoError(request);
        assertValidState(request, response);

        // Retrieve stored origin domain and issuer from the authorization flow
        String originDomain = TransientCookieStore.getOriginDomain(request, response);
        String originIssuer = TransientCookieStore.getOriginIssuer(request, response);

        if (originDomain == null) {
            originDomain = domainProvider.getDomain(request);
        }

        if (originIssuer == null) {
            originIssuer = constructIssuer(originDomain);
        }

        // Each request will create its own verification options with the correct issuer
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
     * 
     * @param request            the HTTP request
     * @param response           the HTTP response
     * @param frontChannelTokens the tokens obtained from the front channel
     * @param responseTypeList   the reponse types
     * @param originDomain       the domain for this specific request
     * @param originIssuer       the issuer for this specific request
     * @return a Tokens object that wraps the values obtained from the front-channel
     *         and/or the code request response.
     * @throws IdentityVerificationException
     */
    private Tokens getVerifiedTokens(HttpServletRequest request, HttpServletResponse response,
            Tokens frontChannelTokens,
            List<String> responseTypeList, String originDomain, String originIssuer)
            throws IdentityVerificationException {

        String authorizationCode = request.getParameter(KEY_CODE);
        Tokens codeExchangeTokens = null;

        // Get nonce for this specific request
        String nonce = response != null
                ? (TransientCookieStore.getNonce(request, response) != null
                        ? TransientCookieStore.getNonce(request, response)
                        : RandomStorage.removeSessionNonce(request))
                : RandomStorage.removeSessionNonce(request);

        IdTokenVerifier.Options requestVerifyOptions = createRequestVerifyOptions(originIssuer, nonce);

        try {
            if (responseTypeList.contains(KEY_ID_TOKEN)) {
                // Implicit/Hybrid flow: must verify front-channel ID Token first
                validateIdTokenIssuer(frontChannelTokens.getIdToken(), originIssuer);
                tokenVerifier.verify(frontChannelTokens.getIdToken(), requestVerifyOptions);
            }
            if (responseTypeList.contains(KEY_CODE)) {
                // Code/Hybrid flow
                String redirectUri = request.getRequestURL().toString();
                codeExchangeTokens = exchangeCodeForTokens(authorizationCode, redirectUri, originDomain);
                if (!responseTypeList.contains(KEY_ID_TOKEN)) {
                    // If we already verified the front-channel token, don't verify it again.
                    String idTokenFromCodeExchange = codeExchangeTokens.getIdToken();
                    if (idTokenFromCodeExchange != null) {
                        validateIdTokenIssuer(idTokenFromCodeExchange, originIssuer);
                        tokenVerifier.verify(idTokenFromCodeExchange, requestVerifyOptions);
                    }
                }
            }
        } catch (TokenValidationException e) {
            throw new IdentityVerificationException(JWT_VERIFICATION_ERROR,
                    "An error occurred while trying to verify the ID Token.", e);
        } catch (Auth0Exception e) {
            throw new IdentityVerificationException(API_ERROR,
                    "An error occurred while exchanging the authorization code.", e);
        }
        // Keep the front-channel ID Token and the code-exchange Access Token.
        return mergeTokens(frontChannelTokens, codeExchangeTokens);
    }

    /**
     * Creates per-request verification options to avoid thread safety issues.
     * This creates fresh options from the stored configuration values.
     */
    private IdTokenVerifier.Options createRequestVerifyOptions(String issuer, String nonce) {
        // Create fresh verification options for this specific request
        IdTokenVerifier.Options requestOptions = new IdTokenVerifier.Options(clientId, signatureVerifier);

        requestOptions.setIssuer(issuer);
        requestOptions.setNonce(nonce);

        if (clockSkew != null) {
            requestOptions.setClockSkew(clockSkew);
        }
        if (authenticationMaxAge != null) {
            requestOptions.setMaxAge(authenticationMaxAge);
        }
        if (organization != null) {
            requestOptions.setOrganization(organization);
        }

        return requestOptions;
    }

    /**
     * Validates that the ID Token's issuer matches the expected origin issuer.
     *
     * @param idToken        the ID Token to validate
     * @param expectedIssuer the expected issuer from the authorization flow
     * @throws IdentityVerificationException if the issuer doesn't match
     */
    private void validateIdTokenIssuer(String idToken, String expectedIssuer) throws IdentityVerificationException {
        if (idToken == null || expectedIssuer == null) {
            return;
        }

        try {
            String[] parts = idToken.split("\\.");
            if (parts.length != 3) {
                throw new IdentityVerificationException(JWT_VERIFICATION_ERROR, "Invalid ID Token format", null);
            }

            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            String tokenIssuer = extractIssuerFromPayload(payload);

            if (!tokenIssuer.equals(expectedIssuer)) {
                throw new IdentityVerificationException(JWT_VERIFICATION_ERROR,
                        String.format("Token issuer '%s' does not match expected issuer '%s'",
                                tokenIssuer, expectedIssuer),
                        null);
            }
        } catch (Exception e) {
            if (e instanceof IdentityVerificationException) {
                throw e;
            }
            throw new IdentityVerificationException(JWT_VERIFICATION_ERROR,
                    "Failed to validate token issuer: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts the issuer (iss) claim from the ID Token payload.
     *
     * @param payload the decoded payload of the ID Token
     * @return the issuer claim value
     * @throws IdentityVerificationException if the issuer claim is missing
     */
    private String extractIssuerFromPayload(String payload) throws IdentityVerificationException {
        try {
            Map<String, Object> payloadMap = new ObjectMapper().readValue(payload,
                    new TypeReference<Map<String, Object>>() {
                    });
            if (payloadMap.containsKey("iss")) {
                return payloadMap.get("iss").toString();
            } else {
                throw new IdentityVerificationException(JWT_VERIFICATION_ERROR,
                        "Issuer claim (iss) is missing in the ID Token payload.", null);
            }
        } catch (Exception e) {
            throw new IdentityVerificationException(JWT_VERIFICATION_ERROR,
                    "Failed to parse ID Token payload: " + e.getMessage(), e);
        }
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
     * Extract the tokens from the request parameters, present when using the
     * Implicit or Hybrid Grant.
     *
     * @param request      the request
     * @param originDomain the domain that issued these tokens
     * @param originIssuer the issuer that issued these tokens
     * @return a new instance of Tokens wrapping the values present in the request
     *         parameters.
     */
    private Tokens getFrontChannelTokens(HttpServletRequest request, String originDomain, String originIssuer) {
        Long expiresIn = request.getParameter(KEY_EXPIRES_IN) == null ? null
                : Long.parseLong(request.getParameter(KEY_EXPIRES_IN));
        return new Tokens(request.getParameter(KEY_ACCESS_TOKEN), request.getParameter(KEY_ID_TOKEN), null,
                request.getParameter(KEY_TOKEN_TYPE), expiresIn, originDomain, originIssuer);
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
     * Checks whether the state received in the request parameters is the same as
     * the one in the state cookie or session
     * for this request.
     *
     * @param request the request
     * @throws InvalidRequestException if the request contains a different state
     *                                 from the expected one
     */
    private void assertValidState(HttpServletRequest request, HttpServletResponse response)
            throws InvalidRequestException {
        // TODO in v2:
        // - only store state/nonce in cookies, remove session storage
        // - create specific exception classes for various state validation failures
        // (missing from auth response, missing
        // state cookie, mismatch)

        String stateFromRequest = request.getParameter(KEY_STATE);

        if (stateFromRequest == null) {
            throw new InvalidRequestException(INVALID_STATE_ERROR,
                    "The received state doesn't match the expected one. No state parameter was found on the authorization response.");
        }

        // If response is null, check the Session.
        // This can happen when the deprecated handle method that only takes the request
        // parameter is called
        if (response == null) {
            checkSessionState(request, stateFromRequest);
            return;
        }

        String cookieState = TransientCookieStore.getState(request, response);

        // Just in case state was stored in Session by building auth URL with deprecated
        // method, but then called the
        // supported handle method with the request and response
        if (cookieState == null) {
            if (SessionUtils.get(request, StorageUtils.STATE_KEY) == null) {
                throw new InvalidRequestException(INVALID_STATE_ERROR,
                        "The received state doesn't match the expected one. No state cookie or state session attribute found. Check that you are using non-deprecated methods and that cookies are not being removed on the server.");
            }
            checkSessionState(request, stateFromRequest);
            return;
        }

        if (!cookieState.equals(stateFromRequest)) {
            throw new InvalidRequestException(INVALID_STATE_ERROR,
                    "The received state doesn't match the expected one.");
        }
    }

    private void checkSessionState(HttpServletRequest request, String stateFromRequest) throws InvalidRequestException {
        boolean valid = RandomStorage.checkSessionState(request, stateFromRequest);
        if (!valid) {
            throw new InvalidRequestException(INVALID_STATE_ERROR,
                    "The received state doesn't match the expected one.");
        }
    }

    /**
     * Calls the Auth0 Authentication API to perform a Code Exchange.
     *
     * @param authorizationCode the code received on the login response.
     * @param redirectUri       the redirect uri used on login request.
     * @param originDomain      the domain that issued these tokens.
     * @return a new instance of {@link Tokens} with the received credentials.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     * @see AuthAPI#exchangeCode(String, String)
     */
    private Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri, String originDomain)
            throws Auth0Exception {
        AuthAPI client = createClientForDomain(originDomain);
        TokenHolder holder = client
                .exchangeCode(authorizationCode, redirectUri)
                .execute();
        String originIssuer = constructIssuer(originDomain);
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(), holder.getTokenType(),
                holder.getExpiresIn(), originDomain, originIssuer);
    }

    /**
     * Used to keep the best version of each token.
     * It will prioritize the ID Token received in the front-channel, and the Access
     * Token received in the code exchange request.
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
        String idToken = frontChannelTokens.getIdToken() != null ? frontChannelTokens.getIdToken()
                : codeExchangeTokens.getIdToken();

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