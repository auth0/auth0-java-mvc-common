package com.auth0.test;

import com.auth0.AuthenticationController;
import com.auth0.IdentityVerificationException;
import com.auth0.Tokens;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;

/*NOTE
THis is added just for testing purpose, will be removed before merging to master. This is /callback endpoint configured
*/
@WebServlet(urlPatterns = {"/callback"})
public class CallbackServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        AuthenticationController controller = Auth0Provider.getController();

        try {

            System.out.println("CallbackServlet: Handling callback request for authentication.");

            Tokens tokens = controller.handle(req, resp);

            resp.getWriter().write("Login Successful! Welcome");

        } catch (IdentityVerificationException e) {
            resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            resp.getWriter().write("Authentication failed: " + e.getMessage());
        }
    }
}