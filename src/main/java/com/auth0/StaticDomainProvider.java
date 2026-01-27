package com.auth0;

import javax.servlet.http.HttpServletRequest;

public class StaticDomainProvider implements DomainProvider {
    private final String domain;

    StaticDomainProvider(String domain) {
        this.domain = domain;
    }

    @Override
    public String getDomain(HttpServletRequest request) {
        return domain;
    }
}
