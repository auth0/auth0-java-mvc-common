package com.auth0;

@SuppressWarnings("unused")
class AlgorithmNameVerifier extends SignatureVerifier {

    AlgorithmNameVerifier() {
        //Must only allow supported algorithms and never "none" algorithm
        super(null, "HS256", "RS256");
    }
}
