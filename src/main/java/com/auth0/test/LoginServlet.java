package com.auth0.test;

import com.auth0.AuthenticationController;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*NOTE
THis is added just for testing purpose, will be removed before merging to master. This is login endpoint configured.
*/
@WebServlet(urlPatterns = {"/login"})
public class LoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        AuthenticationController controller = Auth0Provider.getController();

        String scheme = req.getScheme();
        String serverName = req.getServerName();
        int serverPort = req.getServerPort();

        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(serverName);

        // Only add port if it's not standard (80/443)
        if ((scheme.equals("http") && serverPort != 80) || (scheme.equals("https") && serverPort != 443)) {
            sb.append(":").append(serverPort);
        }
        sb.append("/callback"); // Ensure this matches your dashboard path

        String dynamicCallbackUrl = sb.toString();

        String authorizeUrl = controller
                .buildAuthorizeUrl(req, resp, dynamicCallbackUrl)
                .build();

        resp.sendRedirect(authorizeUrl);

    }

    private String getCallbackUrl(HttpServletRequest req) {
        // Dynamically build callback based on current port: localhost:3000 or 8080
        return String.format("http://%s:%d/callback", req.getServerName(), req.getServerPort());
    }
}