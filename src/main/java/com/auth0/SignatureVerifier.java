package com.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.Validate;

import java.util.Arrays;
import java.util.List;

abstract class SignatureVerifier {

    private final JWTVerifier verifier;
    private final List<String> acceptedAlgorithms;

    /**
     * Creates a new JWT Signature Verifier.
     * This instance will validate the token was signed using an expected algorithm
     * and then proceed to verify its signature
     *
     * @param verifier  the instance that knows how to verify the signature. When null, the signature will not be checked.
     * @param algorithm the accepted algorithms. Must never be null!
     */
    SignatureVerifier(JWTVerifier verifier, String... algorithm) {
        Validate.notEmpty(algorithm);
        this.verifier = verifier;
        this.acceptedAlgorithms = Arrays.asList(algorithm);
    }

    private DecodedJWT decodeToken(String token) throws TokenValidationException {
        try {
            return JWT.decode(token);
        } catch (JWTDecodeException e) {
            throw new TokenValidationException("ID token could not be decoded", e);
        }
    }

    DecodedJWT verifySignature(String token) throws TokenValidationException {
        DecodedJWT decoded = decodeToken(token);
        if (!this.acceptedAlgorithms.contains(decoded.getAlgorithm())) {
            throw new TokenValidationException(String.format("Signature algorithm of \"%s\" is not supported. Expected the ID token to be signed with \"%s\".", decoded.getAlgorithm(), this.acceptedAlgorithms));
        }
        if (verifier != null) {
            try {
                verifier.verify(decoded);
            } catch (SignatureVerificationException e) {
                throw new TokenValidationException("Invalid token signature", e);
            } catch (JWTVerificationException ignored) {
                //NO-OP. Will be catch on a different step
                //Would only trigger for "expired tokens" (invalid exp)
                // ¯\_(ツ)_/¯
            }
        }

        return decoded;
    }
}
