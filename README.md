# Auth0 Java MVC Commons

A Java Jar library that contains common helper classes and api client logic that are used across our Java MVC libraries.

The libraries dependent upon this Jar include:

[Auth0 Servlet](https://github.com/auth0/auth0-servlet)

[Auth0 Spring MVC](https://github.com/auth0/auth0-spring-mvc)

[Auth0 Spring Security MVC](https://github.com/auth0/auth0-spring-security-mvc)


## Download

Via Maven:

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>mvc-auth-commons</artifactId>
    <version>1.0.0</version>
</dependency>
```

or Gradle:

```gradle
compile 'com.auth0:mvc-auth-commons:1.0.0'
```


## Configuration

### Auth0 Dashboard
1. Go to the [Clients Dashboard](https://manage.auth0.com/#/clients) and create a new Client of type **Regular Web Application**. Verify that the "Token Endpoint Authentication Method" is `POST`.
2. Add a valid callback URL to the "Allowed Callback URLs" field. This URL will be called with the authentication result.
3. Add a valid logout URL to the "Allowed Logout URLs" field.
4. Take the `Client Id`, `Domain`, and `Client Secret` values and use them to configure the controller.

### Java Application
5. Use the `AuthenticationController.Builder` class to configure the authentication behavior and build the `AuthenticationController` instance, read [below](#builder-options) for more options. i.e. using the `HS256` Algorithm and Code Grant (default):

```java
try {
    AuthenticationController authController = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
       .build();
} catch (UnsupportedEncodingException e) {
    // Only thrown when using Implicit Grant with HS256 Algorithm.
    // This example is not that case so we can ignore it.
}
```

6. Create a valid "Authorize URL" with `AuthenticationController#buildAuthorizeUrl`. This would normally be done on the component that shows the login page. Redirect the user to this URL and wait for the callback on the `redirectURL`.

```java
String authorizeUrl = authController.buildAuthorizeUrl(request, "https://redirect.uri/here");
// or use custom state/nonce parameters
String authorizeUrl = authController.buildAuthorizeUrl(request, "https://redirect.uri/here", "state", "nonce");
// Now redirect the user to the authorizeUrl
```

7. Pass the requests received in your application to the `AuthenticationController#handle` method and expect a `Tokens` instance back if everything goes well. Keep in mind that this library will not store any value for you, but you can use the `SessionUtils` class as a helper to store key-value data in the Session Storage.

```java
try {
    Tokens tokens = authController.handle(request);
    //Use or store the tokens
    SessionUtils.set(request, "access_token", tokens.getAccessToken());
} catch (IdentityVerificationException e) {
    String code = e.getCode();
    // Something happened when trying to verify the user id
    // Check the code to have an idea of what went wrong
}
```


That's it! You have authenticated the user using Auth0.



### Builder Options
By default, the **Code Grant** flow will be used and preferred over other flows. This is the most secure and recommended way, read more about it [here](https://auth0.com/docs/api-auth/grant/authorization-code). This means that if the response type contains `code` along with other types, the Code Grant will still be preferred.

You can change the authentication behavior to use **Implicit Grant** instead. To do this you'll need to check in your Client's Settings on the [Dashboard](https://manage.auth0.com/#/clients) which Algorithm is used by the Server to sign the tokens. The default algorithm is `HS256`, but it can be changed to `RS256` in the "Advanced Settings" section on the "OAuth" tab. Below you'll find some configuration examples:


#### Using Implicit Grant with HS256 algorithm

The token's are signed using the `Client Secret`.

```java
try {
    AuthenticationController authController = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
        .withResponseType("token id_token")
        .build();
} catch (UnsupportedEncodingException e) {
    // The environment doesn't support UTF-8 encoding 
}
```

#### Using Implicit Grant with RS256 algorithm.

The tokens are signed using the Private Key. To verify them, the **Public Key** certificate must be obtained from a trusted source like the `well-known.json` file, which can be located locally or hosted by a server. For this example, we will use the one Auth0 hosts for your client. We can obtain it using the client's domain:


```java
try {
    JwkProvider jwkProvider = new JwkProviderBuilder("domain").build();
    AuthenticationController authController = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
        .withResponseType("token id_token")
        .withJwkProvider(jwkProvider)
        .build();
} catch (UnsupportedEncodingException e) {
    // Not thrown with RS256 
}
```

The `JwkProvider` returned from the `JwkProviderBuilder` it's cached and rate limited, check it's [repository](https://github.com/auth0/jwks-rsa-java) for custom configuration.


### Troubleshooting

Once you have created the instance of the `AuthenticationController` you can enable HTTP logging for all Requests and Responses if you need to debug a specific endpoint. Keep in mind that this will log everything including sensitive information. Don't use it in production environment.

```java
authController.setLoggingEnabled(true);
```

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
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

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
