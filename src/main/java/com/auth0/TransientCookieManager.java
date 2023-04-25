package com.auth0;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

class TransientCookieManager {

    static void store(HttpServletRequest request, HttpServletResponse response, String state, String nonce, boolean useLegacySameSiteCookie, boolean setSecureCookie, String responseType) {
        if (response != null) {
            SameSite sameSiteValue = containsFormPost(responseType) ? SameSite.NONE : SameSite.LAX;

            TransientCookieStore.storeState(response, state, sameSiteValue, useLegacySameSiteCookie, setSecureCookie);
            TransientCookieStore.storeNonce(response, nonce, sameSiteValue, useLegacySameSiteCookie, setSecureCookie);
        }

        // Also store in Session just in case developer uses deprecated
        // AuthenticationController.handle(HttpServletRequest) API
        RandomStorage.setSessionState(request, state);
        RandomStorage.setSessionNonce(request, nonce);
    }

    private static boolean containsFormPost(String responseType) {
        String[] splitResponseTypes = responseType.trim().split("\\s+");
        List<String> responseTypes = Collections.unmodifiableList(Arrays.asList(splitResponseTypes));
        return RequestProcessor.requiresFormPostResponseMode(responseTypes);
    }
}
