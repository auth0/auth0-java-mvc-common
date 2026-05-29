package com.auth0;

import jakarta.servlet.http.HttpServletRequest;

interface DomainProvider {
    String getDomain(HttpServletRequest request);

}
