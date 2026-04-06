package com.auth0;

import javax.servlet.http.HttpServletRequest;

class ResolverDomainProvider implements DomainProvider {
    private final DomainResolver resolver;

    ResolverDomainProvider(DomainResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public String getDomain(HttpServletRequest request) {
        String domain = resolver.resolve(request);
        if (domain == null || domain.trim().isEmpty()) {
            throw new IllegalStateException("DomainResolver returned a null or empty domain");
        }
        return domain;
    }
}
