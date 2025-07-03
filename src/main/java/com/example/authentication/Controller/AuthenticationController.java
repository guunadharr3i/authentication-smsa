package com.example.authentication.Controller;

import com.example.authentication.Pojo.AuthenticationRequest;
import com.example.authentication.service.AuthenticationService;
import com.example.authentication.Entity.SmsaRole;
import com.example.authentication.Entity.SmsaUser;
import com.example.authentication.service.LdapService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;

@RestController
@RequestMapping
@CrossOrigin(origins = "*")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private LdapService ldapAuthService;

    private static final Logger logger = LogManager.getLogger(AuthenticationController.class);

    @GetMapping("/")
    public String hello(Model model) {
        logger.info("AuthenticationController -> hello endpoint called");
        return "Hey Developer! Authentication Application Deployed Successfully";
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> validateAndRefreshAccessToken(@RequestBody Map<String, String> tokenRequest) {
        logger.info("AuthenticationController -> refresh-token called");
        String oldToken = tokenRequest.get("token");

        if (oldToken == null || oldToken.isEmpty()) {
            logger.warn("No token provided for refresh");
            return ResponseEntity.badRequest().body("Token is required");
        }

        try {
            String newAccessToken = authenticationService.validateToken(oldToken);
            authenticationService.verifyValidateUserDevice(oldToken,newAccessToken,tokenRequest.get("DeviceHash"));
            Map<String, String> response = new HashMap<>();
            response.put("accessToken", newAccessToken);
            logger.info("Token refreshed successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Token refresh failed: {}", e.getMessage(), e);
            return ResponseEntity.status(401).body("Invalid or expired token: " + e.getMessage());
        }
    }
    @PostMapping("/ladp")
    public ResponseEntity<?> ldpLogin(@RequestBody AuthenticationRequest authenticationRequest) throws NamingException {
        logger.info("AuthenticationController -> authenticate called for user: {}", authenticationRequest.getUsername());
        logger.info("Enter in LDAP Authentication");
        SmsaUser ldpData = ldapAuthService.ldapAuthService(authenticationRequest);
        logger.info("Successfully LDAP Authentication is Done");
        return ResponseEntity.status(401).body("Successfully  LDAP Authentication is Done");
    }


        @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws NamingException {
        logger.info("AuthenticationController -> authenticate called for user: {}", authenticationRequest.getUsername());
        logger.info("Enter in LDAP Authentication");
        SmsaUser ldpData=ldapAuthService.ldapAuthService(authenticationRequest);
        logger.info("Successfully LDAP Authentication is Done");

        try {
            boolean isValidUser = validateUser(authenticationRequest.getUsername(), authenticationRequest.getPassword());

            SmsaUser userData = authenticationService.getUserByLoginId(authenticationRequest.getUsername());
            if (!isValidUser) {
                logger.warn("Invalid login attempt for user: {}", authenticationRequest.getUsername());
                return ResponseEntity.status(401).body("Invalid credentials");
            }
            authenticationService.validateUserDevice(authenticationRequest,userData.getAccessToken());

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", userData.getAccessToken());

            logger.info("User authenticated successfully: {}", authenticationRequest.getUsername());
            return ResponseEntity.ok(tokens);

        } catch (Exception e) {
            logger.error("Authentication failed for user: {}", authenticationRequest.getUsername(), e);
            return ResponseEntity.status(500).body("Authentication failed: " + e.getMessage());
        }
    }

    @PostMapping("/user/role")
    public ResponseEntity<?> createUserRole(@RequestBody Map<String, String> requestData) {
        logger.info("AuthenticationController -> user/role called");

        try {
            Map<String, SmsaRole> tokens = new HashMap<>();
            tokens.put("Roles", authenticationService.creteUserRoleData(requestData));

            logger.info("User role created successfully");
            return ResponseEntity.ok(tokens);
        } catch (Exception e) {
            logger.error("Error creating user role", e);
            return ResponseEntity.status(500).body("Error creating user role: " + e.getMessage());
        }
    }

    @PostMapping("/createUser")
    public ResponseEntity<?> createUser(@RequestBody Map<String, String> requestData) {
        logger.info("AuthenticationController -> createUser called");

        try {
            Map<String, SmsaUser> tokens = new HashMap<>();
            tokens.put("User Created", authenticationService.creteUser(requestData));

            logger.info("User created successfully");
            return ResponseEntity.ok(tokens);
        } catch (Exception e) {
            logger.error("Error creating user", e);
            return ResponseEntity.status(500).body("Error creating user: " + e.getMessage());
        }
    }
    @GetMapping("/getUsers")
    public ResponseEntity<?> getUsers() {
        try {
            List<SmsaUser> userList = authenticationService.getUsers();
            logger.info("Users fetched successfully");
            return ResponseEntity.ok(userList);
        } catch (Exception e) {
            logger.error("Error fetching users", e);
            // Return a meaningful error response
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred while fetching users: " + e.getMessage());
        }
    }

    private boolean validateUser(String username, String password) {
        logger.debug("Validating user: {}", username);
        return true;
    }
    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        logger.debug("Inside Logout Method");

        try {
            String token = request.getHeader("Authorization");
            String deviceHash=request.getHeader("DeviceHash");

            if (token == null || token.isEmpty()) {
                logger.warn("Authorization token missing in request header");
                return new ResponseEntity<>("Authorization token is missing", HttpStatus.BAD_REQUEST);
            }

            logger.info("Token received: {}", token);
            return authenticationService.logout(token,deviceHash);

        } catch (Exception e) {
            logger.error("Error occurred during logout: ", e);
            return new ResponseEntity<>("Internal Server Error during logout", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/loginDetails")
    public ResponseEntity<?> userLoginDetails(HttpServletRequest request) {
        logger.debug("Inside loginDetails Method");

        try {
            String token = request.getHeader("Authorization");

            if (token == null || token.isEmpty()) {
                logger.warn("Authorization token missing in request header");
                return new ResponseEntity<>("Authorization token is missing", HttpStatus.BAD_REQUEST);
            }

            logger.info("Received request: {}", token);
            return authenticationService.userLoginDetails(token);

        } catch (Exception e) {
            logger.error("Error occurred during getting loginDetails: ", e);
            return new ResponseEntity<>("Internal Server Error during loginDetails", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
    
