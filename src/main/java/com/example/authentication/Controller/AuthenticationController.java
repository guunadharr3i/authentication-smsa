package com.example.authentication.Controller;

import com.example.authentication.Pojo.AuthenticationRequest;
import com.example.authentication.service.AuthenticationService;
import com.example.authentication.Entity.SmsaRole;
import com.example.authentication.Entity.SmsaUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author abcom
 */
@RestController
@RequestMapping
@CrossOrigin(origins = "*")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;
//    private LdapService ldapService;

    @GetMapping("/")
    public String hello(Model model) {
        return "Hello, welcome to Spring Boot!"; // Refers to hello.html inside templates folder
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> validateAndRefreshAccessToken(@RequestBody Map<String, String> tokenRequest) {
        String oldToken = tokenRequest.get("token");

        if (oldToken == null || oldToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Token is required");
        }

        try {
            String newAccessToken = authenticationService.validateToken(oldToken);
            Map<String, String> response = new HashMap<>();
            response.put("accessToken", newAccessToken);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid or expired token: " + e.getMessage());
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {

        boolean isValidUser = validateUser(authenticationRequest.getUsername(), authenticationRequest.getPassword());

//        SmsaUser ldapData=ldapService.ldapAuthService(authenticationRequest);
        SmsaUser userData = authenticationService.getUserByLoginId(authenticationRequest.getUsername());
        if (!isValidUser) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", userData.getAccessToken());

        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/user/role")
    public ResponseEntity<?> createUserRole(@RequestBody Map<String, String> requestData) throws Exception {

        Map<String, SmsaRole> tokens = new HashMap<>();
        tokens.put("Roles", authenticationService.creteUserRoleData(requestData));

        return ResponseEntity.ok(tokens);
    }

    private boolean validateUser(String username, String password) {
        return true;
    }

    @PostMapping("/createUser")
    public ResponseEntity<?> createUser(@RequestBody Map<String, String> requestData) throws Exception {

        Map<String, SmsaUser> tokens = new HashMap<>();
        tokens.put("User Created", authenticationService.creteUser(requestData));

        return ResponseEntity.ok(tokens);
    }

}
