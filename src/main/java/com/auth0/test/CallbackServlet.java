package com.auth0.test;

import com.auth0.AuthenticationController;
import com.auth0.IdentityVerificationException;
import com.auth0.Tokens;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;

@WebServlet(urlPatterns = {"/callback"})
public class CallbackServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        AuthenticationController controller = Auth0Provider.getController();

        try {
            // 3. The Handle Method
            // This validates the state cookie, exchanges the code for tokens,
            // and performs the dynamic ID token verification.
            Tokens tokens = controller.handle(req, resp);

            // 4. Success: Store in session (Requirement #5)
            HttpSession session = req.getSession(true);
            session.setAttribute("accessToken", tokens.getAccessToken());
            session.setAttribute("idToken", tokens.getIdToken());

            // Note: originDomain is now inside the tokens object
            System.out.println("Authenticated via domain: " + tokens.getDomain());

            resp.getWriter().write("Login Successful! Welcome, " + tokens.getIdToken());

        } catch (IdentityVerificationException e) {
            resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            resp.getWriter().write("Authentication failed: " + e.getMessage());
        }
    }
}
