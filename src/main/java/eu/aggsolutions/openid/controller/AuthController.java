package eu.aggsolutions.openid.controller;

import eu.aggsolutions.openid.components.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final TokenValidator tokenValidator;

    public AuthController(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication, HttpServletRequest request) {
        if (authentication != null && authentication.isAuthenticated()) {
            OAuth2User user = (OAuth2User) authentication.getPrincipal();
            Map<String, Object> attributes = user.getAttributes();

            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("name", attributes.get("name"));
            userInfo.put("email", attributes.get("email"));
            userInfo.put("sub", attributes.get("sub"));

            return ResponseEntity.ok(userInfo);
        }
        // Fallback: validate token from cookie directly
        String token = getTokenFromCookie(request);
        if (token != null) {
            Map<String, Object> userInfo = tokenValidator.getUserInfo(token);
            if (userInfo != null) {
                return ResponseEntity.ok(userInfo);
            }
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response) {
        // Spring Security logout is handled by the security configuration
        Map<String, String> result = new HashMap<>();
        result.put("message", "Logout successful");
        return ResponseEntity.ok(result);
    }

    private String getTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                    .filter(cookie -> "auth_token".equals(cookie.getName()))
                    .map(jakarta.servlet.http.Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }
        return null;
    }

}
