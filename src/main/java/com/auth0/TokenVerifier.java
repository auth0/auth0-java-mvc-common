package com.auth0;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.Validate;

import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

/**
 * Class that verifies the signature of Auth0 issued id tokens.
 */
@SuppressWarnings("WeakerAccess")
class TokenVerifier {

    private final Algorithm algorithm;
    private final JwkProvider jwkProvider;
    private final String audience;
    private final String issuer;
    private JWTVerifier verifier;

    /**
     * Creates a new instance using the HS256 algorithm and the clientSecret as secret.
     *
     * @param clientSecret the Auth0 client secret to validate the signature with.
     * @param clientId     the Auth0 client id that this token is issued for.
     * @param domain       the Auth0 domain that issued this token.
     * @throws UnsupportedEncodingException if the current environment doesn't support UTF-8 encoding.
     */
    public TokenVerifier(String clientSecret, String clientId, String domain) throws UnsupportedEncodingException {
        Validate.notNull(clientSecret);
        Validate.notNull(clientId);
        Validate.notNull(domain);

        this.algorithm = Algorithm.HMAC256(clientSecret);
        this.jwkProvider = null;
        this.audience = clientId;
        this.issuer = toUrl(domain);
    }

    /**
     * Creates a new instance using the RS256 algorithm and the RSA key as secret.
     *
     * @param jwkProvider the JwkProvider of the key to validate the signature with.
     * @param clientId    the Auth0 client id that this token is issued for.
     * @param domain      the Auth0 domain that issued this token.
     */
    public TokenVerifier(JwkProvider jwkProvider, String clientId, String domain) {
        Validate.notNull(jwkProvider);
        Validate.notNull(clientId);
        Validate.notNull(domain);

        this.algorithm = null;
        this.jwkProvider = jwkProvider;
        this.audience = clientId;
        this.issuer = toUrl(domain);
    }

    private DecodedJWT verifyToken(String idToken) throws JwkException {
        if (verifier != null) {
            return verifier.verify(idToken);
        }
        if (algorithm != null) {
            verifier = JWT.require(algorithm)
                    .withAudience(audience)
                    .withIssuer(issuer)
                    .build();
            return verifier.verify(idToken);
        }
        String kid = JWT.decode(idToken).getKeyId();
        PublicKey publicKey = jwkProvider.get(kid).getPublicKey();
        return JWT.require(Algorithm.RSA256((RSAKey) publicKey))
                .withAudience(audience)
                .withIssuer(issuer)
                .build()
                .verify(idToken);
    }

    /**
     * Verify that the idToken contains a claim 'nonce' with the exact given value.
     * If verification passes, the User Id ('sub' claim) is returned.
     *
     * @param idToken the id token to verify
     * @param nonce   the expected nonce value
     * @return the User Id contained in the token
     * @throws JwkException             if the Public Key Certificate couldn't be obtained
     * @throws JWTVerificationException if the Id Token signature was invalid
     */
    public String verifyNonce(String idToken, String nonce) throws JwkException, JWTVerificationException {
        Validate.notNull(idToken);
        Validate.notNull(nonce);

        DecodedJWT jwt = verifyToken(idToken);
        return nonce.equals(jwt.getClaim("nonce").asString()) ? jwt.getSubject() : null;
    }

    private static String toUrl(String domain) {
        String url = domain;
        if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
            url = "https://" + domain;
        }
        if (!url.endsWith("/")) {
            url = url + "/";
        }
        return url;
    }

}
