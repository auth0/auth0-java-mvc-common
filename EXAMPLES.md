# Examples using auth0-java-mvc-common

- [Including additional authorization parameters](#including-additional-authorization-parameters)
- [Organizations](#organizations)
- [Allowing clock skew for token validation](#allow-a-clock-skew-for-token-validation)
- [Changing the OAuth response_type](#changing-the-oauth-response_type)
- [HTTP logging](#http-logging)

## Including additional authorization parameters

Parameters to send on the authorization request can be specified when configuring the authorization URL`:

```java
String authorizeUrl = authController.buildAuthorizeUrl(request, response, "YOUR-REDIRECT-URL")
    .withAudience("https://myapi.me.auth0.com")
    .withScope("openid create:photos read:photos")
    .withParameter("name", "value")
    .build();
```

## Organizations

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.

### Log in to an organization

Log in to an organization by using `withOrganization()` when configuring the `AuthenticationController`, passing either the organization ID or organization name:

```java
AuthenticationController controller = AuthenticationController.newBuilder("YOUR-AUTH0-DOMAIN", "YOUR-CLIENT-ID", "YOUR-CLIENT-SECRET")
        .withOrganization("{ORG_ID}")
        .build();
```

When logging into an organization, this library will validate that the `org_id` or `org_name` claim of the ID Token matches the value configured.

If no organization parameter was given to the authorization endpoint, but an `org_id` or `org_name` claim is present in the ID Token, then the claim should be validated by the application to ensure that the value received is expected or known.

Normally, validating the issuer would be enough to ensure that the token was issued by Auth0, and this check is performed by this SDK.
In the case of organizations, additional checks may be required so that the organization within an Auth0 tenant is expected.

In particular, the `org_id` or `org_name` claim should be checked to ensure it is a value that is already known to the application.
This could be validated against a known list of organizations, or perhaps checked in conjunction with the current request URL (e.g., the sub-domain may hint at what organization should be used to validate the ID Token).

If the claim cannot be validated, then the application should deem the token invalid.
The following example demonstrates this, using the [java-jwt](https://github.com/auth0/java-jwt) library:
```java
// verify org_id using java-jwt, if needing to check against a list of valid organizations
Tokens tokens = authenticationController.handle(req, res);
String idToken = tokens.getIdToken();
List<String> expectedOrgIds = Arrays.asList("ORG_ID_1", "ORG_ID_2");
DecodedJWT jwt = JWT.decode("TOKEN");
String jwtOrgId = jwt.getClaim("org_id").asString();
if (!expectedOrgIds.contains(jwtOrgId)) {
    // token invalid, do not trust
}
```

For more information, please read [Work with Tokens and Organizations](https://auth0.com/docs/organizations/using-tokens) on Auth0 Docs.

### Accept user invitations

Accept a user invitation by using `withInvitation()` when configuring the `AuthenticationController` (you must also specify the organization):

```java
AuthenticationController controller = AuthenticationController.newBuilder("{DOMAIN}", "{CLIENT_ID}", "{CLIENT_SECRET}")
        .withOrganization("ORG_ID")
        .withInvitation("INVITATION_ID")
        .build();
```

The ID of the invitation and organization are available as query parameters on the invitation URL, e.g., `https://your-domain.auth0.com/login?invitation={INVITATION_ID}&organization={ORG_ID}&organization_name={ORG_NAME}`

## Allow a clock skew for token validation

During the authentication flow, the ID token is verified and validated to ensure it is secure. Time-based claims such as the time the token was issued at and the token's expiration are verified to ensure the token is valid.
To accommodate potential small differences in system clocks, this library allows a default of **60 seconds** of clock skew.

You can customize the clock skew as shown below:

```java
AuthenticationController authController = AuthenticationController.newBuilder("YOUR-DOMAIN", "YOUR-CLIENT-ID", "YOUR-CLIENT-SECRET")
    .withClockSkew(60 * 2) // 2 minutes
    .build();
```

## Changing the OAuth response_type

By default, this library uses the `code` response_type. This can be changed by specifying the desired `response_type` on the `AuthenticationController#Builder`:

```java
AuthenticationController authController = AuthenticationController.newBuilder("YOUR-AUTH0-DOMAIN", "YOUR-CLIENT-ID", "YOUR-CLIENT-SECRET")
    .withResponseType("id_token code")
    .build();
```

## HTTP logging

Once you have created the instance of the `AuthenticationController`, you can enable HTTP logging for all Requests and Responses to debug a specific endpoint.
**This will log everything including sensitive information** - do not use it in a production environment.

```java
authController.setLoggingEnabled(true);
```
