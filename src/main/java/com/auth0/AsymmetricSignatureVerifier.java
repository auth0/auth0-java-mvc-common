package com.auth0;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@SuppressWarnings("unused")
class AsymmetricSignatureVerifier extends SignatureVerifier {

    AsymmetricSignatureVerifier(JwkProvider jwkProvider) {
        super(createJWTVerifier(jwkProvider), "RS256");
    }

    private static JWTVerifier createJWTVerifier(final JwkProvider jwkProvider) {
        Algorithm alg = Algorithm.RSA256(new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                try {
                    Jwk jwk = jwkProvider.get(keyId);
                    return (RSAPublicKey) jwk.getPublicKey();
                } catch (JwkException ignored) {
                    //Nothing to do here! :(
                    //TODO: See how to improve the exception handling on the java-jwt side
                }
                return null;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                //NO-OP
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                //NO-OP
                return null;
            }
        });
        return JWT.require(alg)
                .ignoreIssuedAt()
                .build();
    }
}
