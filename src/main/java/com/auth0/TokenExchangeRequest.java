package com.auth0;

import com.auth0.exception.Auth0Exception;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Class to perform a <a href="https://auth0.com/docs/authenticate/custom-token-exchange">Custom
 * Token Exchange</a>: exchanging an external {@code subject_token} for Auth0 {@link Tokens} via the
 * RFC 8693 grant {@code urn:ietf:params:oauth:grant-type:token-exchange}, optionally targeting an
 * {@code audience}, {@code scope}, and/or {@code organization}.
 * <p>
 * The library remains stateless: the application owns storage of the returned tokens.
 * <p>
 * Obtain an instance via {@link AuthenticationController#customTokenExchange(String, String)} /
 * {@link AuthenticationController#loginWithCustomTokenExchange(String, String)} (and their
 * domain-qualified overloads). The {@code loginWith*} variants always verify the returned ID token.
 * The utility variant returns the raw exchanged tokens without verification, except when an
 * organization is configured: to validate the {@code org_id}/{@code org_name} claim it must verify
 * the ID token that carries it, so a returned ID token is fully verified on either path whenever an
 * organization is in play. See {@link #withOrganization(String)}.
 */
@SuppressWarnings({"UnusedReturnValue", "WeakerAccess", "unused"})
public class TokenExchangeRequest {

    private final RequestProcessor processor;
    private final String subjectToken;
    private final String subjectTokenType;
    private final String domain;
    private final String issuer;
    private final boolean loginSemantics;

    private String audience;
    private String scope;
    private String organization;

    TokenExchangeRequest(RequestProcessor processor, String subjectToken, String subjectTokenType,
                         String domain, String issuer, boolean loginSemantics, String organization) {
        this.processor = processor;
        this.subjectToken = subjectToken;
        this.subjectTokenType = subjectTokenType;
        this.domain = domain;
        this.issuer = issuer;
        this.loginSemantics = loginSemantics;
        this.organization = organization;
    }

    /**
     * Sets the audience (API identifier) to request an access token for. When not set, Auth0 uses
     * the default audience configured for the application.
     *
     * @param audience the audience to request a token for.
     * @return this request instance for fluent chaining.
     */
    public TokenExchangeRequest withAudience(String audience) {
        this.audience = audience;
        return this;
    }

    /**
     * Sets the scope to request for the access token.
     *
     * @param scope the requested scope.
     * @return this request instance for fluent chaining.
     */
    public TokenExchangeRequest withScope(String scope) {
        this.scope = scope;
        return this;
    }

    /**
     * Sets the organization to associate with the exchange, overriding any client-level default
     * configured on the {@link AuthenticationController}. When an organization is set, the returned
     * ID token's {@code org_id}/{@code org_name} claim is validated against this value on both the
     * {@code loginWith*} and the utility path (whenever the exchange returns an ID token). Because
     * an organization claim cannot be trusted without verifying the token that carries it, the
     * utility path performs full ID-token verification (signature, issuer, expiry) in this case, so
     * an {@link IdentityVerificationException} may be thrown even when only an access token was
     * wanted.
     *
     * @param organization the organization ID or name.
     * @return this request instance for fluent chaining.
     */
    public TokenExchangeRequest withOrganization(String organization) {
        this.organization = organization;
        return this;
    }

    /**
     * Executes the token exchange against Auth0 and returns the resulting tokens.
     *
     * @return the {@link Tokens} obtained from the exchange, including the granted scope.
     * @throws CustomTokenExchangeException  if the request fails client-side validation.
     * @throws IdentityVerificationException if the exchange fails or, on the {@code loginWith*}
     *                                       path, the returned ID token fails verification.
     * @throws Auth0Exception                if the request to the Auth0 server failed.
     */
    public Tokens execute() throws IdentityVerificationException, Auth0Exception {
        validate();
        return processor.executeCustomTokenExchange(
                subjectToken, subjectTokenType, audience, scope, organization,
                domain, issuer, loginSemantics);
    }

    private void validate() throws CustomTokenExchangeException {
        assertValidTokenFormat(subjectToken);
        assertValidTokenTypeUri(subjectTokenType);
    }

    private void assertValidTokenFormat(String token) throws CustomTokenExchangeException {
        if (token == null || token.trim().isEmpty()) {
            throw new CustomTokenExchangeException(CustomTokenExchangeException.INVALID_TOKEN_FORMAT,
                    "The subject token must not be empty.");
        }
        // Reject surrounding whitespace so a stray space/newline can't slip a malformed token
        // through (and so a leading space doesn't hide a "Bearer " prefix from the check below).
        if (!token.equals(token.trim())) {
            throw new CustomTokenExchangeException(CustomTokenExchangeException.INVALID_TOKEN_FORMAT,
                    "The subject token must not contain leading or trailing whitespace.");
        }
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new CustomTokenExchangeException(CustomTokenExchangeException.INVALID_TOKEN_FORMAT,
                    "The subject token must not carry a \"Bearer \" prefix.");
        }
    }

    private void assertValidTokenTypeUri(String tokenType) throws CustomTokenExchangeException {
        if (tokenType == null || tokenType.trim().isEmpty()) {
            throw new CustomTokenExchangeException(CustomTokenExchangeException.INVALID_TOKEN_TYPE_URI,
                    "The subject token type must be a valid URI.");
        }
        try {
            URI uri = new URI(tokenType);
            if (!uri.isAbsolute()) {
                throw new CustomTokenExchangeException(CustomTokenExchangeException.INVALID_TOKEN_TYPE_URI,
                        "The subject token type must be an absolute URI.");
            }
        } catch (URISyntaxException e) {
            throw new CustomTokenExchangeException(CustomTokenExchangeException.INVALID_TOKEN_TYPE_URI,
                    "The subject token type must be a valid URI.");
        }
    }
}
