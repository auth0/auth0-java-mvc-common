package com.auth0;

import javax.servlet.http.HttpServletRequest;

public interface DomainResolver {
    /**
     * Resolves the domain to be used for the current request.
     * @param request the current HttpServletRequest
     * @return a single domain string (e.g., "tenant.auth0.com")
     */
    String resolve(HttpServletRequest request);
}
