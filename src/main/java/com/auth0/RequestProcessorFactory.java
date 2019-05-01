package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;
import com.auth0.net.Telemetry;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang3.Validate;

import java.io.UnsupportedEncodingException;

class RequestProcessorFactory {

    RequestProcessor forCodeGrant(String domain, String clientId, String clientSecret, String responseType) {
        Validate.notNull(domain);
        Validate.notNull(clientId);
        Validate.notNull(clientSecret);
        Validate.notNull(responseType);

        AuthAPI client = new AuthAPI(domain, clientId, clientSecret);
        setupTelemetry(client);
        return new RequestProcessor(client, responseType, null);
    }

    RequestProcessor forImplicitGrant(String domain, String clientId, String clientSecret, String responseType) throws UnsupportedEncodingException {
        Validate.notNull(domain);
        Validate.notNull(clientId);
        Validate.notNull(clientSecret);
        Validate.notNull(responseType);

        AuthAPI client = new AuthAPI(domain, clientId, clientSecret);
        setupTelemetry(client);
        TokenVerifier verifier = new TokenVerifier(clientSecret, clientId, domain);
        return new RequestProcessor(client, responseType, verifier);
    }

    RequestProcessor forImplicitGrant(String domain, String clientId, String clientSecret, String responseType, JwkProvider provider) {
        Validate.notNull(domain);
        Validate.notNull(clientId);
        Validate.notNull(clientSecret);
        Validate.notNull(responseType);
        Validate.notNull(provider);

        AuthAPI client = new AuthAPI(domain, clientId, clientSecret);
        setupTelemetry(client);
        TokenVerifier verifier = new TokenVerifier(provider, clientId, domain);
        return new RequestProcessor(client, responseType, verifier);
    }

    @VisibleForTesting
    void setupTelemetry(AuthAPI client) {
        Telemetry telemetry = new Telemetry("auth0-java-mvc-common", obtainPackageVersion());
        client.setTelemetry(telemetry);
    }

    @VisibleForTesting
    String obtainPackageVersion() {
        //Value if taken from jar's manifest file.
        //Call will return null on dev environment (outside of a jar)
        return RequestProcessorFactory.class.getPackage().getImplementationVersion();
    }
}
