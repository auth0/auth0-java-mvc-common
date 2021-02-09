# Auth0 Java MVC Commons

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/auth0-java-mvc-common.svg?style=flat-square)](https://circleci.com/gh/auth0/auth0-java-mvc-common/tree/master)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/auth0-java-mvc-common.svg?style=flat-square)](https://codecov.io/github/auth0/auth0-java-mvc-common)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](http://doge.mit-license.org)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fauth0%2Fauth0-java-mvc-common.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fauth0%2Fauth0-java-mvc-common?ref=badge_shield)

A Java Jar library that makes easier to integrate Auth0 Authentication on MVC applications.

See the [Java Servlet Quickstart](https://auth0.com/docs/quickstart/webapp/java) to learn how to use this library in a Servlet application.

> If you are using Spring Boot 2, it is recommended to use the OIDC support available in Spring, instead of using this library. See the [Spring Boot Quickstart](https://auth0.com/docs/quickstart/webapp/java-spring-boot) for more information.

## Download

Via Maven:

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>mvc-auth-commons</artifactId>
    <version>1.4.1</version>
</dependency>
```

or Gradle:

```gradle
implementation 'com.auth0:mvc-auth-commons:1.4.1'
```


## Configuration

### Auth0 Dashboard
1. Go to the Auth0 [Applications Dashboard](https://manage.auth0.com/#/applications) and create a new Application of type **Regular Web Application**. Verify that the "Token Endpoint Authentication Method" is set to `POST`.
2. Add a valid callback URL to the "Allowed Callback URLs" field. This URL will be called with the authentication result.
3. Take the `Client Id`, `Domain`, and `Client Secret` values and use them to configure the controller.

### Java Application
4. Create a new `AuthenticationController` by using the provided Builder. Read [below](#builder-options) to learn how to change the default behavior. i.e. using the `HS256` Algorithm and Code Grant (default):
```java
AuthenticationController controller = AuthenticationController.newBuilder("domain", "client_id", "client_secret")
            .build();
```
5. Create a valid "Authorize URL" using the `AuthenticationController#buildAuthorizeUrl` method. This would normally be done on the component that shows the login page. The builder allows you to customize the parameters requested (i.e. the scope, which by default is `openid`) and then obtain the String authorize URL by calling `AuthorizeURL#build()`. **The builder is not supposed to be reused and a `IllegalStateException` will be thrown if the `build()` method is called more than once.** Redirect the user to this URL and wait for the callback on the given `redirectURL`.  

```java
//let the library generate the state/nonce parameters
String authorizeUrl = authController.buildAuthorizeUrl(request, response, "https://redirect.uri/here")
    .build();

// or use custom state/nonce parameters
String authorizeUrl = authController.buildAuthorizeUrl(request, response, "https://redirect.uri/here")
    .withState("state")
    .withNonce("nonce")
    .build();

// you can also specify custom parameters
String authorizeUrl = authController.buildAuthorizeUrl(request, response, "https://redirect.uri/here")
    .withAudience("https://myapi.me.auth0.com")
    .withScope("openid create:photos read:photos")
    .withParameter("name", "value")
    .build();
```

6. The user will be presented with the Auth0 Hosted Login page in which he'll prompt his credentials and authenticate. Your application must expect a call to the `redirectURL`. 
7. Pass the received request to the `AuthenticationController#handle` method and expect a `Tokens` instance back if everything goes well. 

**Keep in mind that this library will not store any value for you, but you can use the `SessionUtils` class as a helper to store key-value data in the request's Session Storage.**

```java
try {
    Tokens tokens = authController.handle(request, response);
    //Use or store the tokens
    request.getSession().setAttribute("access_token", tokens.getAccessToken());
} catch (IdentityVerificationException e) {
    String code = e.getCode();
    // Something happened when trying to process the request.
    // Could be a bad request, an error from the server, 
    // or a configuration issue that triggered a failure. 
    // Check the exception code to have an idea of what went wrong.
}
```


That's it! You have authenticated the user using Auth0.



### Builder options

By default, this library will execute the [Open ID Connect](https://openid.net/specs/openid-connect-core-1_0-final.html) **Authorization Code Flow** and verify the ID token (if received) using the **HS256 symmetric algorithm**.

#### Signing Algorithms

The **HS256 symmetric algorithm** is the default expected signing algorithm. Tokens are signed and verified using the client secret found in your Auth0 Application's settings. You use this value when you instantiate the `AuthenticationController` instance.

If your application is using the **RS256 asymmetric algorithm**, tokens are signed using a private key and verified using the public key associated with your Auth0 domain.
If using RS256, configure a `JwkProvider` for your Auth0 domain to enable retrieving the public key needed during the verification phase: 


```java
JwkProvider jwkProvider = new JwkProviderBuilder("domain").build();
AuthenticationController authController = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
    .withJwkProvider(jwkProvider)
    .build();
```

The `JwkProvider` returned from the `JwkProviderBuilder` is cached and rate limited by default. Please see the [jwks-rsa-java repository](https://github.com/auth0/jwks-rsa-java) to learn how to customize these options.

#### OAuth Flows

The [Authorization Code Flow](https://auth0.com/docs/flows/concepts/auth-code) is the default authorization flow.

To use the [Implicit Grant Flow](https://auth0.com/docs/flows/concepts/implicit), configure the `AuthenticationController` with the `id_token` response type:

```java
AuthenticationController authController = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
    .withResponseType("id_token")
    .build();
```

To use the **[Hybrid Flow](https://auth0.com/docs/api-auth/grant/hybrid)**, specify `id_token code` as the response type:

```java
AuthenticationController authController = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
    .withResponseType("id_token code")
    .build();
```

### Troubleshooting

#### Allowing a clock skew

During ID token validation, time-based claims such as the time the token was issued at and the token's expiration time, are verified to ensure the token is valid. 
To accommodate potential small differences in system clocks, this library allows a default of **60 seconds** of clock skew.

You can customize the clock skew as shown below:     

```java
AuthenticationController authController = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
    .withClockSkew(60 * 2)   //2 minutes
    .build();
```

#### HTTP Logging 
Once you have created the instance of the `AuthenticationController` you can enable HTTP logging for all Requests and Responses to debug a specific endpoint. **This will log everything including sensitive information** so don't use it in a production environment.

```java
authController.setLoggingEnabled(true);
```

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, among others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free account in Auth0

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fauth0%2Fauth0-java-mvc-common.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fauth0%2Fauth0-java-mvc-common?ref=badge_large)