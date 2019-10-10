package com.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;

@SuppressWarnings("unused")
class SymmetricSignatureVerifier extends SignatureVerifier {

    SymmetricSignatureVerifier(String secret) {
        super("HS256", createJWTVerifier(secret));
    }

    private static JWTVerifier createJWTVerifier(String secret) {
        Algorithm alg = Algorithm.HMAC256(secret);
        return JWT.require(alg)
                .ignoreIssuedAt()
                .build();
    }
}
