package com.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

abstract class SignatureVerifier {

    private final String algorithm;
    private JWTVerifier verifier;

    SignatureVerifier(String algorithm, JWTVerifier verifier) {
        this.algorithm = algorithm;
        this.verifier = verifier;
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
        if (!this.algorithm.equals(decoded.getAlgorithm())) {
            throw new TokenValidationException(String.format("Signature algorithm of \"%s\" is not supported. Expected the ID token to be signed with \"%s\".", decoded.getAlgorithm(), this.algorithm));
        }

        try {
            verifier.verify(decoded);
        } catch (SignatureVerificationException e) {
            throw new TokenValidationException("Invalid token signature", e);
        } catch (JWTVerificationException ignored){
            //NO-OP. Will be catch on a different step
            //Would only trigger for "expired tokens" (invalid exp)
            // ¯\_(ツ)_/¯
        }

        return decoded;
    }
}
