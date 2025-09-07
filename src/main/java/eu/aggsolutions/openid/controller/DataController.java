package eu.aggsolutions.openid.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/data")
public class DataController {

    @GetMapping
    public ResponseEntity<Map<String, Object>> getData(Authentication authentication) {
        Map<String, Object> data = new HashMap<>();
        data.put("message", "This is protected data");
        data.put("timestamp", System.currentTimeMillis());
        data.put("user", authentication.getName());

        return ResponseEntity.ok(data);
    }
}
