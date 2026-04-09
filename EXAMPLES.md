# Examples using auth0-java-mvc-common

- [Including additional authorization parameters](#including-additional-authorization-parameters)
- [Organizations](#organizations)
- [Multiple Custom Domains (MCD) Support](#multiple-custom-domains-support)
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

## Multiple Custom Domains Support

Multiple Custom Domains (MCD) lets you resolve the Auth0 domain per request while keeping a single SDK instance. This is useful when one application serves multiple custom domains (for example, `brand-1.my-app.com` and `brand-2.my-app.com`), each mapped to a different `Auth0` custom domain.

`MCD` is enabled by providing a `DomainResolver` function instead of a static domain string, enabling you to dynamically define the `Auth0` custom domain at run-time.

Resolver mode is intended for the custom domains of a single `Auth0` tenant. It is not a supported way to connect multiple `Auth0` tenants to one application.

### Dynamic Domain Resolver

Provide a resolver function to select the domain at runtime. The resolver should return the `Auth0 Custom Domain` (for example, `brand-1.custom-domain.com`). Returning `null` or an empty value throws `IllegalStateException`.

### Configure with a DomainResolver

Implement the `DomainResolver` interface to resolve the domain dynamically based on the incoming request. The domain can be derived from a subdomain, request header, query parameter, or any other request attribute:

```java
DomainResolver domainResolver = (HttpServletRequest request) -> {
    // Example: resolve from a custom header
    String tenant = request.getHeader("X-Tenant-Domain");
    return tenant != null ? tenant : "default-tenant.auth0.com";
};

AuthenticationController controller = AuthenticationController
        .newBuilder(domainResolver, "YOUR-CLIENT-ID", "YOUR-CLIENT-SECRET")
        .build();
```

### Resolve domain from subdomain

```java
DomainResolver domainResolver = (HttpServletRequest request) -> {
    // e.g., "acme.myapp.com" -> "acme.auth0.com"
    String host = request.getServerName();
    String subdomain = host.split("\\.")[0];
    return subdomain + ".auth0.com";
};

AuthenticationController controller = AuthenticationController
        .newBuilder(domainResolver, "YOUR-CLIENT-ID", "YOUR-CLIENT-SECRET")
        .build();
```

### Building the authorize URL and handling the callback

The login and callback servlets work the same way as with a static domain. The library automatically stores the resolved domain and issuer in transient cookies during the authorization flow, and retrieves them when handling the callback:

```java
// LoginServlet - domain is resolved automatically per request
@WebServlet(urlPatterns = {"/login"})
public class LoginServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String authorizeUrl = controller
                .buildAuthorizeUrl(req, res, "https://myapp.com/callback")
                .build();
        res.sendRedirect(authorizeUrl);
    }
}

// CallbackServlet - domain/issuer retrieved from cookies and validated
@WebServlet(urlPatterns = {"/callback"})
public class CallbackServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        try {
            Tokens tokens = controller.handle(req, res);

            // Access the domain and issuer that were used for this authentication
            String domain = tokens.getDomain();   // e.g., "acme.auth0.com"
            String issuer = tokens.getIssuer();    // e.g., "https://acme.auth0.com/"

            // Use domain/issuer for tenant-specific session management
            req.getSession().setAttribute("auth0_domain", domain);

            res.sendRedirect("/dashboard");
        } catch (IdentityVerificationException e) {
            // handle authentication error
        }
    }
}
```

### How it works

1. When `buildAuthorizeUrl()` is called, the `DomainResolver` resolves the domain from the current request. The resolved domain and its issuer are stored as transient cookies (`com.auth0.origin_domain`, `com.auth0.origin_issuer`).
2. When the callback is handled via `handle()`, the stored domain and issuer are retrieved from cookies. The library creates a domain-specific API client for the code exchange and validates that the ID token's `iss` claim matches the expected issuer.
3. The returned `Tokens` object includes `getDomain()` and `getIssuer()` for use in tenant-specific logic.

### Redirect URI requirements

When using MCD, the `redirectUri` passed to `buildAuthorizeUrl()` must be an **absolute URL**. The SDK does not infer it from the request. In MCD deployments, you will typically resolve the redirect URI per request so each domain uses the correct callback URL:

```java
@Override
protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
    // Resolve redirect URI based on the incoming request's host
    String redirectUri = req.getScheme() + "://" + req.getServerName() + "/callback";

    String authorizeUrl = controller
            .buildAuthorizeUrl(req, res, redirectUri)
            .build();
    res.sendRedirect(authorizeUrl);
}
```

You must validate the host and scheme safely for your deployment to prevent open redirect attacks.

### Legacy sessions and migration

When moving from a static domain setup to a `DomainResolver`, existing sessions can continue to work if the resolver returns the same Auth0 custom domain that was used for those legacy sessions.

If the resolver returns a different domain, the SDK treats the session as missing and requires the user to sign in again. This is intentional to keep sessions isolated per domain.

### Security requirements

When configuring the `DomainResolver`, you are responsible for ensuring that all resolved domains are trusted. Mis-configuring the domain resolver is a critical security risk that can lead to authentication bypass on the relying party (RP) or expose the application to Server-Side Request Forgery (SSRF).

**Single tenant limitation:**
The `DomainResolver` is intended solely for multiple custom domains belonging to the same Auth0 tenant. It is not a supported mechanism for connecting multiple Auth0 tenants to a single application.

**Secure proxy requirement:**
When using MCD, your application must be deployed behind a secure edge or reverse proxy (e.g., Cloudflare, Nginx, or AWS ALB). The proxy must be configured to sanitize and overwrite `Host` and `X-Forwarded-Host` headers before they reach your application.

Without a trusted proxy layer to validate these headers, an attacker can manipulate the domain resolution process. This can result in malicious redirects, where users are sent to unauthorized or fraudulent endpoints during the login and logout flows.

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
