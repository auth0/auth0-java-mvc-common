# Change Log

## [1.0.11](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.11) (2019-09-26)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.10...1.0.11)

**Security**
- Update dependencies to address CVE [\#41](https://github.com/auth0/auth0-java-mvc-common/pull/41) ([jimmyjames](https://github.com/jimmyjames))

## [1.0.10](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.10) (2019-08-15)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.9...1.0.10)

**Security**
- Update to latest Auth0 dependencies [\#39](https://github.com/auth0/auth0-java-mvc-common/pull/39) ([jimmyjames](https://github.com/jimmyjames))

## [1.0.9](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.9) (2019-07-03)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.8...1.0.9)

**Security**
- Update to latest auth0-java [\#35](https://github.com/auth0/auth0-java-mvc-common/pull/35) ([jimmyjames](https://github.com/jimmyjames))

## [1.0.8](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.8) (2019-06-04)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.7...1.0.8)

**Fixed**
- Rollback to fixed dependencies versions [\#33](https://github.com/auth0/auth0-java-mvc-common/pull/33) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.7](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.7) (2019-05-23)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.6...1.0.7)

**Security**
- Update dependencies [\#31](https://github.com/auth0/auth0-java-mvc-common/pull/31) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.6](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.6) (2019-05-02)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.5...1.0.6)

**Fixed**
- Allow telemetry to dynamically obtain the package version [\#28](https://github.com/auth0/auth0-java-mvc-common/pull/28) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.5](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.5) (2019-04-17)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.4...1.0.5)

**Changed**
- Bump dependencies [\#26](https://github.com/auth0/auth0-java-mvc-common/pull/26) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.4](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.4) (2019-03-11)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.3...1.0.4)

**Fixed**
- Revert auth0 dependencies scope to api (compile) [\#24](https://github.com/auth0/auth0-java-mvc-common/pull/24) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.3](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.3) (2019-01-03)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.2...1.0.3)

**Security**
- Bump Auth0 dependencies to fix security issue [\#20](https://github.com/auth0/auth0-java-mvc-common/pull/20) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.2](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.2) (2018-10-24)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.1...1.0.2)

**Security**
- Update dependencies  [\#16](https://github.com/auth0/auth0-java-mvc-common/pull/16) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.1](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.1) (2018-06-13)
[Full Changelog](https://github.com/auth0/auth0-java-mvc-common/compare/1.0.0...1.0.1)

**Security**
- Use latest auth0-java, java-jwt and jwks-rsa libraries [\#11](https://github.com/auth0/auth0-java-mvc-common/pull/11) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.0](https://github.com/auth0/auth0-java-mvc-common/tree/1.0.0) (2017-05-24)

Reworked the library to support both **Code Grant** and **Implicit Grant** authentication flows by using the latest [Auth0-Java](https://github.com/auth0/auth0-java/) SDK. 

The changes from v0 includes:

- Simpler setup and configuration
- Use of Auth0 Hosted Login page and OAuth 2.0 endpoints for Authentication
- Support **Code Grant** and **Implicit Grant** flows.
- Support Public Key Rotation when verifying Token signatures (Implicit Grant)
