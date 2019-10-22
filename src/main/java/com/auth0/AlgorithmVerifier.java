package com.auth0;

@SuppressWarnings("unused")
class AlgorithmVerifier extends SignatureVerifier {

    AlgorithmVerifier() {
        //Must only allow supported algorithms and never "none" algorithm
        super(null, "HS256", "RS256");
    }
}
