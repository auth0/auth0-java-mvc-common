![Auth0 SDK to add authentication to your Java Servlet applications.](https://cdn.auth0.com/website/sdks/banners/auth0-java-mvc-common-banner.png)

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/auth0-java-mvc-common.svg?style=flat-square)](https://circleci.com/gh/auth0/auth0-java-mvc-common/tree/master)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/auth0-java-mvc-common.svg?style=flat-square)](https://codecov.io/github/auth0/auth0-java-mvc-common)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](https://doge.mit-license.org/)
[![Maven Central](https://img.shields.io/maven-central/v/com.auth0/mvc-auth-commons.svg?style=flat-square)](https://mvnrepository.com/artifact/com.auth0/mvc-auth-commons)
[![javadoc](https://javadoc.io/badge2/com.auth0/auth0-java-mvc-common/javadoc.svg)](https://javadoc.io/doc/com.auth0/mvc-auth-commons)

:books: [Documentation](#documentation) - :rocket: [Getting Started](#getting-started) - :computer: [API Reference](#api-reference) :speech_balloon: [Feedback](#feedback)

## Documentation

- [Quickstart](https://auth0.com/docs/quickstart/webapp/java) - our interactive guide for quickly adding login, logout and user information to a Java Servlet application using Auth0.
- [Sample App](https://github.com/auth0-samples/auth0-servlet-sample/tree/master/01-Login) - a sample Java Servlet application integrated with Auth0.
- [Examples](./EXAMPLES.md) - code samples for common scenarios.
- [Docs site](https://www.auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### Requirements

Java 8 or above and `javax.servlet` version 3.

> If you are using Spring, we recommend leveraging Spring's OIDC and OAuth2 support, as demonstrated by the [Spring Boot Quickstart](https://auth0.com/docs/quickstart/webapp/java-spring-boot).

### Installation

Add the dependency via Maven:

```xml
<dependency>
  <groupId>com.auth0</groupId>
  <artifactId>mvc-auth-commons</artifactId>
  <version>1.9.2</version>
</dependency>
```

or Gradle:

```gradle
implementation 'com.auth0:mvc-auth-commons:1.9.2'
```

### Configure Auth0

Create a **Regular Web Application** in the [Auth0 Dashboard](https://manage.auth0.com/#/applications). Verify that the "Token Endpoint Authentication Method" is set to `POST`.

Next, configure the callback and logout URLs for your application under the "Application URIs" section of the "Settings" page:

- **Allowed Callback URLs**: The URL of your application where Auth0 will redirect to during authentication, e.g., `http://localhost:3000/callback`.
- **Allowed Logout URLs**: The URL of your application where Auth0 will redirect to after user logout, e.g., `http://localhost:3000/login`.

Note the **Domain**, **Client ID**, and **Client Secret**. These values will be used later.

### Add login to your application

Create a new `AuthenticationController` using your Auth0 domain, and Auth0 application client ID and secret.
Configure the builder with a `JwkProvider` for your Auth0 domain.

```java
public class AuthenticationControllerProvider {
    private String domain = "YOUR-AUTH0-DOMAIN";
    private String clientId = "YOUR-CLIENT-ID";
    private String clientSecret = "YOUR-CLIENT-SECRET";
    
    private AuthenticationController authenticationController;
    
    static {
        JwkProvider jwkProvider = new JwkProviderBuilder("YOUR-AUTH0-DOMAIN").build();
        authenticationController = AuthenticationController.newBuilder(domain, clientId, clientSecret)
                .withJwkProvider(jwkProvider)
                .build();
    }
    
    public getInstance() {
        return authenticationController;
    }
}
```

> Note: The `AuthenticationController.Builder` is not to be reused, and an `IllegalStateException` will be thrown if `build()` is called more than once.

Redirect users to the Auth0 login page using the `AuthenticationController`:

```java
@WebServlet(urlPatterns = {"/login"})
public class LoginServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {
        // Where your application will handle the authoriztion callback
        String redirectUrl = "http://localhost:3000/callback";

        String authorizeUrl = AuthenticationControllerProvider
                .getInstance()
                .buildAuthorizeUrl(req, res, redirectUrl)
                .build();
        res.sendRedirect(authorizeUrl);
    }
}
```

Finally, complete the authentication and obtain the tokens by calling `handle()` on the `AuthenticationController`.

```java
@WebServlet(urlPatterns = {"/callback"})
public class CallbackServlet extends HttpServlet {
    
    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        try {
            // authentication complete; the tokens can be stored as needed
            Tokens tokens = AuthenticationControllerProvider
                    .getInstance()
                    .handle(req, res);
            res.sendRedirect("URL-AFTER-AUTHENTICATED");
        } catch (IdentityVerificationException e) {
            // handle authentication error
        }
    }
}
```

That's it! You have authenticated the user using Auth0.

## API Reference

- [JavaDocs](https://javadoc.io/doc/com.auth0/mvc-auth-commons)

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)

### Raise an issue
To provide feedback or report a bug, [please raise an issue on our issue tracker](https://github.com/auth0/auth0-java-mvc-common/issues).

### Vulnerability Reporting
Please do not report security vulnerabilities on the public Github issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png"   width="150">
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a></p>
<p align="center">
This project is licensed under the MIT license. See the <a href="./LICENSE"> LICENSE</a> file for more info.</p>
