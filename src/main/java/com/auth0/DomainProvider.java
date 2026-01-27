package com.auth0;

import javax.servlet.http.HttpServletRequest;

public interface DomainProvider {
    String getDomain(HttpServletRequest request);

}
