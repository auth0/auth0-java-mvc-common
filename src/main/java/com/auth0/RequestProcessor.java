package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;

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

    // Visible for testing
    final IdTokenVerifier.Options verifyOptions;
    final boolean useLegacySameSiteCookie;

    private final String responseType;
    private final AuthAPI client;
    private final IdTokenVerifier tokenVerifier;

    static class Builder {
        final AuthAPI client;
        final String responseType;
        final IdTokenVerifier.Options verifyOptions;
        boolean useLegacySameSiteCookie = true;
        IdTokenVerifier tokenVerifier;

        Builder(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions) {
            Validate.notNull(client);
            Validate.notNull(responseType);
            Validate.notNull(verifyOptions);
            this.client = client;
            this.responseType = responseType;
            this.verifyOptions = verifyOptions;
        }

        Builder withLegacySameSiteCookie(boolean useLegacySameSiteCookie) {
            this.useLegacySameSiteCookie = useLegacySameSiteCookie;
            return this;
        }

        Builder withIdTokenVerifier(IdTokenVerifier verifier) {
            this.tokenVerifier = verifier;
            return this;
        }

        RequestProcessor build() {
            return new RequestProcessor(client, responseType, verifyOptions,
                    this.tokenVerifier == null ? new IdTokenVerifier() : this.tokenVerifier,
                    useLegacySameSiteCookie);
        }
    }

    private RequestProcessor(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions, IdTokenVerifier tokenVerifier, boolean useLegacySameSiteCookie) {
        Validate.notNull(client);
        Validate.notNull(responseType);
        Validate.notNull(verifyOptions);
        this.client = client;
        this.responseType = responseType;
        this.verifyOptions = verifyOptions;
        this.tokenVerifier = tokenVerifier;
        this.useLegacySameSiteCookie = useLegacySameSiteCookie;
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

    /**
     * Pre builds an Auth0 Authorize Url with the given redirect URI, state and nonce parameters.
     *
     * @param request     the request, used to store state and nonce in the Session
     * @param response    the response, used to set state and nonce as cookies. If null, session will be used instead.
     * @param redirectUri the url to call with the authentication result.
     * @param state       a valid state value.
     * @param nonce       the nonce value that will be used if the response type contains 'id_token'. Can be null.
     * @return the authorize url builder to continue any further parameter customization.
     */
    AuthorizeUrl buildAuthorizeUrl(HttpServletRequest request, HttpServletResponse response, String redirectUri,
                                   String state, String nonce) {

        AuthorizeUrl creator = new AuthorizeUrl(client, request, response, redirectUri, responseType)
                .withState(state);

        // null response means state and nonce will be stored in session, so legacy cookie flag does not apply
        if (response != null) {
            creator.withLegacySameSiteCookie(useLegacySameSiteCookie);
        }

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
        assertValidState(request, response);

        Tokens frontChannelTokens = getFrontChannelTokens(request);
        List<String> responseTypeList = getResponseType();

        if (responseTypeList.contains(KEY_ID_TOKEN) && frontChannelTokens.getIdToken() == null) {
            throw new InvalidRequestException(MISSING_ID_TOKEN, "ID Token is missing from the response.");
        }
        if (responseTypeList.contains(KEY_TOKEN) && frontChannelTokens.getAccessToken() == null) {
            throw new InvalidRequestException(MISSING_ACCESS_TOKEN, "Access Token is missing from the response.");
        }

        String nonce;
        if (response != null) {
            // Nonce dynamically set and changes on every request.
            nonce = TransientCookieStore.getNonce(request, response, useLegacySameSiteCookie);

            // Just in case the developer created the authorizeUrl that stores state/nonce in the session
            if (nonce == null) {
                nonce = RandomStorage.removeSessionNonce(request);
            }
        } else {
            nonce = RandomStorage.removeSessionNonce(request);
        }

        verifyOptions.setNonce(nonce);

        return getVerifiedTokens(request, frontChannelTokens, responseTypeList);
    }

    static boolean requiresFormPostResponseMode(List<String> responseType) {
        return responseType != null &&
                (responseType.contains(KEY_TOKEN) || responseType.contains(KEY_ID_TOKEN));
    }

    /**
     * Obtains code request tokens (if using Code flow) and validates the ID token.
     * @param request the HTTP request
     * @param frontChannelTokens the tokens obtained from the front channel
     * @param responseTypeList the reponse types
     * @return a Tokens object that wraps the values obtained from the front-channel and/or the code request response.
     * @throws IdentityVerificationException
     */
    private Tokens getVerifiedTokens(HttpServletRequest request, Tokens frontChannelTokens, List<String> responseTypeList)
            throws IdentityVerificationException {

        String authorizationCode = request.getParameter(KEY_CODE);
        Tokens codeExchangeTokens = null;

        try {
            if (responseTypeList.contains(KEY_ID_TOKEN)) {
                // Implicit/Hybrid flow: must verify front-channel ID Token first
                tokenVerifier.verify(frontChannelTokens.getIdToken(), verifyOptions);
            }
            if (responseTypeList.contains(KEY_CODE)) {
                // Code/Hybrid flow
                String redirectUri = request.getRequestURL().toString();
                codeExchangeTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
                if (!responseTypeList.contains(KEY_ID_TOKEN)) {
                    // If we already verified the front-channel token, don't verify it again.
                    String idTokenFromCodeExchange = codeExchangeTokens.getIdToken();
                    if (idTokenFromCodeExchange != null) {
                        tokenVerifier.verify(idTokenFromCodeExchange, verifyOptions);
                    }
                }
            }
        } catch (TokenValidationException e) {
            throw new IdentityVerificationException(JWT_VERIFICATION_ERROR, "An error occurred while trying to verify the ID Token.", e);
        } catch (Auth0Exception e) {
            throw new IdentityVerificationException(API_ERROR, "An error occurred while exchanging the authorization code.", e);
        }
        // Keep the front-channel ID Token and the code-exchange Access Token.
        return mergeTokens(frontChannelTokens, codeExchangeTokens);
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
        if (verifyOptions.getMaxAge() != null) {
            creator.withParameter(KEY_MAX_AGE, verifyOptions.getMaxAge().toString());
        }
        return creator;
    }

    /**
     * Extract the tokens from the request parameters, present when using the Implicit or Hybrid Grant.
     *
     * @param request the request
     * @return a new instance of Tokens wrapping the values present in the request parameters.
     */
    private Tokens getFrontChannelTokens(HttpServletRequest request) {
        Long expiresIn = request.getParameter(KEY_EXPIRES_IN) == null ? null : Long.parseLong(request.getParameter(KEY_EXPIRES_IN));
        return new Tokens(request.getParameter(KEY_ACCESS_TOKEN), request.getParameter(KEY_ID_TOKEN), null, request.getParameter(KEY_TOKEN_TYPE), expiresIn);
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
     * Checks whether the state received in the request parameters is the same as the one in the state cookie or session
     * for this request.
     *
     * @param request the request
     * @throws InvalidRequestException if the request contains a different state from the expected one
     */
    private void assertValidState(HttpServletRequest request, HttpServletResponse response) throws InvalidRequestException {
        String stateFromRequest = request.getParameter(KEY_STATE);

        // If response is null, check the Session.
        // This can happen when the deprecated handle method that only takes the request parameter is called
        if (response == null) {
            checkSessionState(request, stateFromRequest);
            return;
        }

        String cookieState = TransientCookieStore.getState(request, response, useLegacySameSiteCookie);

        // Just in case state was stored in Session by building auth URL with deprecated method, but then called the
        // supported handle method with the request and response
        if (cookieState == null) {
            checkSessionState(request, stateFromRequest);
            return;
        }

        if (!cookieState.equals(stateFromRequest)) {
            throw new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one.");
        }
    }

    private void checkSessionState(HttpServletRequest request, String stateFromRequest) throws InvalidRequestException {
        boolean valid = RandomStorage.checkSessionState(request, stateFromRequest);
        if (!valid) {
            throw new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one.");
        }
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
    private Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        TokenHolder holder = client
                .exchangeCode(authorizationCode, redirectUri)
                .execute();
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(), holder.getTokenType(), holder.getExpiresIn());
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

        return new Tokens(accessToken, idToken, refreshToken, type, expiresIn);
    }

}