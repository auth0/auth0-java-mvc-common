package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.auth.UserInfo;
import com.auth0.jwk.JwkException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.auth0.IdentityVerificationException.*;
import static com.auth0.InvalidRequestException.INVALID_STATE_ERROR;
import static com.auth0.InvalidRequestException.MISSING_AUTHORIZATION_CODE_ERROR;

/**
 * Main class to handle the Authorize Redirect request.
 * It will try to parse the parameters looking for tokens or an authorization code to perform a Code Exchange against the Auth0 servers.
 * When the tokens are obtained, it will request the user id associated to them and save it in the {@link javax.servlet.http.HttpSession}.
 */
class RequestProcessor {

    private static final String KEY_SUB = "sub";
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
    final AuthAPI client;
    final String responseType;
    final TokenVerifier verifier;

    RequestProcessor(AuthAPI client, String responseType, TokenVerifier verifier) {
        Validate.notNull(client);
        Validate.notNull(responseType);
        this.client = client;
        this.responseType = responseType;
        this.verifier = verifier;
    }

    List<String> getResponseType() {
        return Arrays.asList(responseType.split(" "));
    }

    /**
     * Getter for the AuthAPI client instance.
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
     * 1). Responsible for validating the request and ensuring the state value in session storage matches the state value passed to this endpoint.
     * 2). Exchanging the authorization code received with this HTTP request for auth0 tokens.
     * 3). Getting the user information associated to the id_token/access_token.
     * 4). Storing both tokens and user information into session storage.
     * 5). Clearing the stored state value.
     * 6). Handling success and any failure outcomes.
     *
     * @throws IdentityVerificationException if an error occurred while processing the request
     */
    Tokens process(HttpServletRequest req) throws IdentityVerificationException {
        assertNoError(req);
        assertValidState(req);

        Tokens tokens = tokensFromRequest(req);
        String authorizationCode = req.getParameter(KEY_CODE);

        String userId;
        if (authorizationCode == null && verifier == null) {
            throw new InvalidRequestException(MISSING_AUTHORIZATION_CODE_ERROR, "Authorization Code is missing from the request and Implicit Grant is not allowed.");
        } else if (verifier != null) {
            if (getResponseType().contains(KEY_ID_TOKEN)) {
                String expectedNonce = RandomStorage.removeSessionNonce(req);
                try {
                    userId = verifier.verifyNonce(tokens.getIdToken(), expectedNonce);
                } catch (JwkException e) {
                    throw new IdentityVerificationException(JWT_MISSING_PUBLIC_KEY_ERROR, "An error occurred while trying to verify the Id Token.", e);
                } catch (JWTVerificationException e) {
                    throw new IdentityVerificationException(JWT_VERIFICATION_ERROR, "An error occurred while trying to verify the Id Token.", e);
                }
            } else {
                try {
                    userId = fetchUserId(tokens.getAccessToken());
                } catch (Auth0Exception e) {
                    throw new IdentityVerificationException(API_ERROR, "An error occurred while trying to verify the Access Token.", e);
                }
            }
        } else {
            String redirectUri = getRedirectUri(req);
            try {
                Tokens latestTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
                tokens = mergeTokens(tokens, latestTokens);
                userId = fetchUserId(tokens.getAccessToken());
            } catch (Auth0Exception e) {
                throw new IdentityVerificationException(API_ERROR, "An error occurred while exchanging the Authorization Code for Auth0 Tokens.", e);
            }
        }

        if (userId == null) {
            throw new IdentityVerificationException("An error occurred while trying to verify the user identity: The 'sub' claim contained in the token was null.");
        }

        return tokens;
    }

    /**
     * Extract the tokens from the request parameters, present when using the Implicit Grant.
     *
     * @param req the request
     * @return a new instance of Tokens wrapping the values present in the request parameters.
     */
    private Tokens tokensFromRequest(HttpServletRequest req) {
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
     * Calls the Auth0 Authentication API to get the User Id.
     *
     * @param accessToken the access token to get the user id for.
     * @return the user id.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     * @see AuthAPI#userInfo(String)
     */
    private String fetchUserId(String accessToken) throws Auth0Exception {
        UserInfo info = client
                .userInfo(accessToken)
                .execute();
        return info.getValues().containsKey(KEY_SUB) ? (String) info.getValues().get(KEY_SUB) : null;
    }


    /**
     * Used to keep the best version of each token. If present, latest tokens will always be better than the first ones.
     *
     * @param tokens       the first obtained tokens.
     * @param latestTokens the latest obtained tokens, preferred over the first ones.
     * @return a merged version of Tokens using the latest tokens when possible.
     */
    private Tokens mergeTokens(Tokens tokens, Tokens latestTokens) {
        String accessToken = latestTokens.getAccessToken() != null ? latestTokens.getAccessToken() : tokens.getAccessToken();
        String idToken = latestTokens.getIdToken() != null ? latestTokens.getIdToken() : tokens.getIdToken();
        String refreshToken = latestTokens.getRefreshToken() != null ? latestTokens.getRefreshToken() : tokens.getRefreshToken();
        String type = latestTokens.getType() != null ? latestTokens.getType() : tokens.getType();
        Long expiresIn = latestTokens.getExpiresIn() != null ? latestTokens.getExpiresIn() : tokens.getExpiresIn();
        return new Tokens(accessToken, idToken, refreshToken, type, expiresIn);
    }

    private String getRedirectUri(HttpServletRequest req) {
        try {
            URI requestUri = new URI(req.getRequestURL().toString());
            String scheme = MoreObjects.firstNonNull(
                req.getHeader("X-Forwarded-Proto"), requestUri.getScheme());
            String port = null;
            String host = MoreObjects.firstNonNull(
                req.getHeader("X-Forwarded-Host"), requestUri.getHost());
            if (host.contains(":")) {
                // X-forwarded-host
                String[] hostAndPort = host.split(":");
                host = hostAndPort[0];
                port = hostAndPort[1];
            }
            if (port == null) {
                port = MoreObjects.firstNonNull(
                    req.getHeader("X-Forwarded-Port"), "" + requestUri.getPort());
            }
            // Make sure to omit the default port
            final Map<String, String> ports = ImmutableMap.of(
                "http", "80",
                "https", "443"
            );
            if (port.equals(ports.get(scheme.toLowerCase()))) {
                port = "-1";
            }
            return new URI(scheme,
                requestUri.getUserInfo(), host, Integer.parseInt(port, 10),
                requestUri.getPath(), requestUri.getQuery(),
                requestUri.getFragment()).toString();
        } catch (URISyntaxException e) {
            return req.getRequestURL().toString();
        }
    }
}
