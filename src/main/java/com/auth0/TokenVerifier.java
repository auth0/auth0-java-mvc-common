package com.auth0;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang3.Validate;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.util.regex.Pattern;

/**
 * Class that verifies the signature of Auth0 issued id tokens.
 */
@SuppressWarnings("WeakerAccess")
class TokenVerifier {

    private static final String NONE_ALGORITHM = "none";
    private final Algorithm algorithm;
    private final JwkProvider jwkProvider;
    private final String audience;
    private final String issuer;
    private Pattern algPattern;
    private JWTVerifier verifier;

    /**
     * Creates a new instance that will not verify the signature. Use as a shortcut for Code flows where the signature validation
     * can be skipped given the TLS server validation already happened.
     * See https://openid.net/specs/openid-connect-core-1_0-final.html#IDTokenValidation
     *
     * @param clientId the Auth0 application's client id that this token is issued for.
     * @param domain   the Auth0 domain that issued this token.
     */
    public TokenVerifier(String clientId, String domain) {
        Validate.notNull(clientId);
        Validate.notNull(domain);

        this.algPattern = Pattern.compile("rs256|hs256", Pattern.CASE_INSENSITIVE);
        this.algorithm = Algorithm.none();
        this.jwkProvider = null;
        this.audience = clientId;
        this.issuer = toUrl(domain);
    }

    /**
     * Creates a new instance using the HS256 algorithm and the application's Client Secret as secret.
     *
     * @param clientSecret the Auth0 application's client secret to validate the signature with.
     * @param clientId     the Auth0 application's client id that this token is issued for.
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
     * @param clientId    the Auth0 application's client id that this token is issued for.
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
        DecodedJWT decoded = JWT.decode(idToken);
        if (verifier != null) {
            //HS256 scenario
            return verifier.verify(decoded);
        }
        if (algorithm == null) {
            //RS256 scenario
            String kid = decoded.getKeyId();
            PublicKey publicKey = jwkProvider.get(kid).getPublicKey();
            return JWT.require(Algorithm.RSA256((RSAKey) publicKey))
                    .withAudience(audience)
                    .withIssuer(issuer)
                    .build()
                    .verify(idToken);
        }
        if (NONE_ALGORITHM.equals(algorithm.getName())) {
            //RS256/HS256 scenario without signature check
            decoded = updateTokenHeader(decoded);
            JWTVerifier noneVerifier = JWT.require(algorithm)
                    .withAudience(audience)
                    .withIssuer(issuer)
                    .build();
            return noneVerifier.verify(decoded);
        }

        //HS256 scenario (First time used)
        verifier = JWT.require(algorithm)
                .withAudience(audience)
                .withIssuer(issuer)
                .build();
        return verifier.verify(decoded);
    }

    /**
     * Replaces the Header's algorithm with "none" and removes the Token's signature.
     * Use only when the authenticity of the token was already verified by the TLS server.
     *
     * @param decoded the original JWT, already decoded.
     * @return a JWT with the "none" algorithm, also decoded.
     */
    private DecodedJWT updateTokenHeader(DecodedJWT decoded) {
        String headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(decoded.getHeader()));
        String updatedHeaderJson = algPattern.matcher(headerJson).replaceFirst(NONE_ALGORITHM);
        String updatedHeader = Base64.encodeBase64URLSafeString(updatedHeaderJson.getBytes(StandardCharsets.UTF_8));
        return JWT.decode(String.format("%s.%s.", updatedHeader, decoded.getPayload()));
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
