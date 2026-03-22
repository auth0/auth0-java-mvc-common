package com.auth0;

import javax.servlet.http.HttpServletRequest;

class ResolverDomainProvider implements DomainProvider {
    private final DomainResolver resolver;

    ResolverDomainProvider(DomainResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public String getDomain(HttpServletRequest request) {
        return resolver.resolve(request);
    }
}
