package com.auth0;

import javax.servlet.http.HttpServletRequest;

interface DomainProvider {
    String getDomain(HttpServletRequest request);

}
