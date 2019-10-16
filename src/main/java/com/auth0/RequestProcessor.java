package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

import static com.auth0.IdentityVerificationException.API_ERROR;
import static com.auth0.IdentityVerificationException.JWT_VERIFICATION_ERROR;
import static com.auth0.InvalidRequestException.INVALID_STATE_ERROR;

/**
 * Main class to handle the Authorize Redirect request.
 * It will try to parse the parameters looking for tokens or an authorization code to perform a Code Exchange against the Auth0 servers.
 * When the tokens are obtained, it will request the user id associated to them and save it in the {@link javax.servlet.http.HttpSession}.
 */
class RequestProcessor {

    private static final String KEY_STATE = "state";
    private static final String KEY_ERROR = "error";
    private static final String KEY_ERROR_DESCRIPTION = "error_description";
    private static final String KEY_EXPIRES_IN = "expires_in";
    private static final String KEY_ACCESS_TOKEN = "access_token";
    private static final String KEY_ID_TOKEN = "id_token";
    private static final String KEY_REFRESH_TOKEN = "refresh_token";
    private static final String KEY_TOKEN_TYPE = "token_type";
    private static final String KEY_CODE = "code";
    private static final String KEY_TOKEN = "token";
    private static final String KEY_RESPONSE_MODE = "response_mode";
    private static final String KEY_FORM_POST = "form_post";

    //Visible for testing
    final IdTokenVerifier.Options verifyOptions;
    private final String responseType;
    private final AuthAPI client;
    private final IdTokenVerifier tokenVerifier;

    @VisibleForTesting
    RequestProcessor(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions, IdTokenVerifier tokenVerifier) {
        Validate.notNull(client);
        Validate.notNull(responseType);
        Validate.notNull(verifyOptions);
        this.client = client;
        this.responseType = responseType;
        this.verifyOptions = verifyOptions;
        this.tokenVerifier = tokenVerifier;
    }

    RequestProcessor(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions) {
        this(client, responseType, verifyOptions, new IdTokenVerifier());
    }

    //TODO: Should we create this instance ONLY on this class? e.g. helper class to instantiate the required+customizable claims
    //static IdTokenVerifier.Options createOptions(){};

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
     * @param request     the caller request. Used to keep the session context.
     * @param redirectUri the url to call with the authentication result.
     * @param state       a valid state value.
     * @param nonce       the nonce value that will be used if the response type contains 'id_token'. Can be null.
     * @return the authorize url builder to continue any further parameter customization.
     */
    AuthorizeUrl buildAuthorizeUrl(HttpServletRequest request, String redirectUri, String state, String nonce) {
        AuthorizeUrl creator = new AuthorizeUrl(client, request, redirectUri, responseType)
                .withState(state);

        List<String> responseTypeList = getResponseType();
        if (responseTypeList.contains(KEY_ID_TOKEN) && nonce != null) {
            creator.withNonce(nonce);
        }
        if (responseTypeList.contains(KEY_TOKEN) || responseTypeList.contains(KEY_ID_TOKEN)) {
            creator.withParameter(KEY_RESPONSE_MODE, KEY_FORM_POST);
        }
        return creator;
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
    Tokens process(HttpServletRequest req) throws IdentityVerificationException {
        assertNoError(req);
        assertValidState(req);

        Tokens frontChannelTokens = getFrontChannelTokens(req);
        Tokens codeExchangeTokens = frontChannelTokens;
        List<String> responseTypeList = getResponseType();

        //TODO: Do we want to use InvalidRequestException here ?
        if (responseTypeList.contains(KEY_ID_TOKEN) && frontChannelTokens.getIdToken() == null) {
            throw new IdentityVerificationException("Id Token is missing from the response.");
        }
        if (responseTypeList.contains(KEY_TOKEN) && frontChannelTokens.getAccessToken() == null) {
            throw new IdentityVerificationException("Access Token is missing from the response.");
        }

        String expectedNonce = RandomStorage.removeSessionNonce(req);
        String authorizationCode = req.getParameter(KEY_CODE);
        String idToken = frontChannelTokens.getIdToken();

        //Dynamically set. Changes on every request!
        verifyOptions.setNonce(expectedNonce);

        try {
            if (responseTypeList.contains(KEY_ID_TOKEN)) {
                //Implicit/Hybrid flow: must verify front-channel ID Token first
                tokenVerifier.verify(idToken, verifyOptions);
            }
            if (responseTypeList.contains(KEY_CODE)) {
                //Code/Hybrid flow
                String redirectUri = req.getRequestURL().toString();
                codeExchangeTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
                if (!responseTypeList.contains(KEY_ID_TOKEN)) {
                    //If already verified the front-channel token, don't verify it again.
                    idToken = codeExchangeTokens.getIdToken();
                    if (idToken != null) {
                        tokenVerifier.verify(idToken, verifyOptions);
                    }
                }
            }

        } catch (JWTVerificationException e) {
            throw new IdentityVerificationException(JWT_VERIFICATION_ERROR, "An error occurred while trying to verify the Id Token.", e);
        } catch (Auth0Exception e) {
            throw new IdentityVerificationException(API_ERROR, "An error occurred while exchanging the Authorization Code for Auth0 Tokens.", e);
        }
        //Keep the front-channel ID Token and the code-exchange Access Token.
        return mergeTokens(frontChannelTokens, codeExchangeTokens);
    }

    List<String> getResponseType() {
        return Arrays.asList(responseType.split(" "));
    }

    /**
     * Extract the tokens from the request parameters, present when using the Implicit or Hybrid Grant.
     *
     * @param req the request
     * @return a new instance of Tokens wrapping the values present in the request parameters.
     */
    private Tokens getFrontChannelTokens(HttpServletRequest req) {
        Long expiresIn = req.getParameter(KEY_EXPIRES_IN) == null ? null : Long.parseLong(req.getParameter(KEY_EXPIRES_IN));
        return new Tokens(req.getParameter(KEY_ACCESS_TOKEN), req.getParameter(KEY_ID_TOKEN), req.getParameter(KEY_REFRESH_TOKEN), req.getParameter(KEY_TOKEN_TYPE), expiresIn);
    }

    /**
     * Checks for the presence of an error in the request parameters
     *
     * @param req the request
     * @throws InvalidRequestException if the request contains an error
     */
    private void assertNoError(HttpServletRequest req) throws InvalidRequestException {
        String error = req.getParameter(KEY_ERROR);
        if (error != null) {
            String errorDescription = req.getParameter(KEY_ERROR_DESCRIPTION);
            throw new InvalidRequestException(error, errorDescription);
        }
    }

    /**
     * Checks whether the state persisted in the session matches the state value received in the request parameters.
     *
     * @param req the request
     * @throws InvalidRequestException if the request contains a different state from the expected one
     */
    private void assertValidState(HttpServletRequest req) throws InvalidRequestException {
        String stateFromRequest = req.getParameter(KEY_STATE);
        boolean valid = RandomStorage.checkSessionState(req, stateFromRequest);
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
        //Prefer access token from the code exchange
        String accessToken = codeExchangeTokens.getAccessToken() != null ? codeExchangeTokens.getAccessToken() : frontChannelTokens.getAccessToken();
        //Prefer id token from the front-channel
        String idToken = frontChannelTokens.getIdToken() != null ? frontChannelTokens.getIdToken() : codeExchangeTokens.getIdToken();
        String refreshToken = frontChannelTokens.getRefreshToken() != null ? frontChannelTokens.getRefreshToken() : codeExchangeTokens.getRefreshToken();
        String type = frontChannelTokens.getType() != null ? frontChannelTokens.getType() : codeExchangeTokens.getType();
        Long expiresIn = frontChannelTokens.getExpiresIn() != null ? frontChannelTokens.getExpiresIn() : codeExchangeTokens.getExpiresIn();
        return new Tokens(accessToken, idToken, refreshToken, type, expiresIn);
    }

}
