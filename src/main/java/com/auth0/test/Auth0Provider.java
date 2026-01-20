package com.auth0.test;

import com.auth0.AuthenticationController;
import com.auth0.DomainResolver;

public class Auth0Provider {

    private static AuthenticationController controller;

    public static synchronized AuthenticationController getController() {
        if (controller == null) {

            DomainResolver mcdResolver = (request) -> {
                return "dummy";
            };

            controller = AuthenticationController
                    .newBuilder(mcdResolver,
                            "ClientID",
                            "ClientSecret")
                    .build();

            System.out.println("Created AuthenticationController with MCD DomainResolver "+controller.toString());

        }
        return controller;
    }
}
