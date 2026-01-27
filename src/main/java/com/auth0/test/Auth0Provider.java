package com.auth0.test;

import com.auth0.AuthenticationController;
import com.auth0.DomainResolver;

import java.util.HashMap;
import java.util.Map;

public class Auth0Provider {

    private static AuthenticationController controller;

    public static synchronized AuthenticationController getController() {
        if (controller == null) {

            DomainResolver mcdResolver = (request) -> {
                return "domain";
            };

            controller = AuthenticationController
                    .newBuilder(mcdResolver,
                            "<CLIENT_ID>",
                            "<CLIENT_SECRET>")
                    .build();

            System.out.println("Created AuthenticationController with MCD DomainResolver "+controller.toString());

        }
        return controller;
    }
}