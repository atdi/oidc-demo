package eu.aggsolutions.openid.components;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final TokenExtractionService tokenService;

    public OAuth2AuthenticationSuccessHandler(TokenExtractionService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        // Get Keycloak access token
        String accessToken = tokenService.getAccessToken(authentication);
        String refreshToken = tokenService.getRefreshToken(authentication);

        if (accessToken != null) {
            // Set access token as HTTP-only cookie
            Cookie accessTokenCookie = new Cookie("auth_token", accessToken);
            accessTokenCookie.setHttpOnly(true);
            accessTokenCookie.setSecure(false); // Set to true in production with HTTPS
            accessTokenCookie.setPath("/");
            accessTokenCookie.setMaxAge(3600); // 1 hour or token expiry time

            response.addCookie(accessTokenCookie);
        }

        if (refreshToken != null) {
            // Set refresh token as HTTP-only cookie
            Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(false);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(86400); // 24 hours or refresh token expiry

            response.addCookie(refreshTokenCookie);
        }

        response.sendRedirect("http://localhost:5173");
    }

}


