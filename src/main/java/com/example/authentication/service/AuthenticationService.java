package com.example.authentication.service;

import com.example.authentication.CustomExceptions.CustomException;
import com.example.authentication.CustomExceptions.SmsaErrorCodes;
import com.example.authentication.Pojo.UserLoginDetailsResponse;
import com.example.authentication.Repo.SmsaRoleRepository;
import com.example.authentication.Repo.UserRepository;
import com.example.authentication.Entity.SmsaRole;
import com.example.authentication.Entity.SmsaUser;
import com.example.authentication.Entity.UserSessionToken;
import com.example.authentication.Pojo.AuthenticationRequest;
import com.example.authentication.Repo.UserSessionTokenRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Service
public class AuthenticationService {

    private static final Logger logger = LogManager.getLogger(AuthenticationService.class);

    private final UserRepository userRepository;
    private final SmsaRoleRepository smsaRoleRepository;
    private final UserSessionTokenRepository userSessionTokenRepository;

    private static final String SECRET_KEY = "mySuperSecureSecretKeyThatIsAtLeast32Bytes!";
    private static final long EXPIRATION_TIME = 10 * 60 * 3000; // 30 minutes
    private static final long REFRESH_TOKEN_EXPIRATION = 7 * 24 * 60 * 60 * 1000; //

    @Value("${aes.encryption.key}")
    private String encryptionKey;

    @Value("${aes.encryption.iv}")
    private String iv;

    private SecretKeySpec keySpec;
    private IvParameterSpec ivSpec;
//    private static final String encrypt="";

    //    private static final String ALGO = "AES";
    public static String ALGORITHM = "AES/CBC/PKCS5Padding"; // 7 days
    @Autowired
    private ObjectMapper objectMapper;

    public AuthenticationService(UserRepository userRepository, SmsaRoleRepository smsaRoleRepository, UserSessionTokenRepository userSessionTokenRepository) {
        this.userRepository = userRepository;
        this.smsaRoleRepository = smsaRoleRepository;
        this.userSessionTokenRepository = userSessionTokenRepository;
    }

    public SmsaUser getUserByLoginId(String loginId) {
        logger.info("Fetching user by loginId: {}", loginId);

        if (loginId == null || loginId.trim().isEmpty()) {
            logger.error("Username must not be null or empty");
            throw new IllegalArgumentException("Username must not be null or empty.");
        }

        SmsaUser user = userRepository.findByLoginId(loginId);

        if (user == null) {
            logger.warn("User not found for loginId: {}", loginId);
            throw new RuntimeException("Username not found for login: " + loginId);
        }

        String token = generateAccessToken(user);
        user.setAccessToken(token);
        logger.info("Generated access token for user: {}", loginId);

        return userRepository.save(user);
    }

    private static Key getSigningKey() {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    public String generateAccessToken(SmsaUser userData) {
        logger.debug("Generating access token for: {}", userData.getLoginId());

        return Jwts.builder()
                .setSubject("access")
                .setIssuedAt(new Date())
                .setId(userData.getLoginId())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken() {
        logger.info("Generating refresh token");

        return Jwts.builder()
                .setSubject("refresh")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String validateToken(String token) throws JwtException {
        logger.info("Validating token");

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String loginId = claims.getId();
            SmsaUser data = userRepository.findByLoginId(loginId);
            if (data.getAccessToken().isEmpty() && data.getAccessToken() == null) {
                throw new CustomException(SmsaErrorCodes.UN_AUTHORIZED, "Token invalid or user logged out");
            }

            if (loginId == null || loginId.isEmpty()) {
                logger.error("Token does not contain valid login ID");
                throw new JwtException("Token does not contain a valid login ID");
            }

            String newJwt = generateAccessToken(data);
            data.setAccessToken(newJwt);
            userRepository.save(data);

            logger.info("Token validated and refreshed for loginId: {}", loginId);
            return newJwt;

        } catch (JwtException e) {
            logger.error("Token validation failed: {}", e.getMessage(), e);
            throw new JwtException("Token validation failed: " + e.getMessage());
        }
    }

    public SmsaRole creteUserRoleData(Map<String, String> requestData) {
        logger.info("Creating new user role");

        try {
            SmsaRole role = new SmsaRole();
            role.setRoleName(requestData.get("ROLE_NAME"));
            role.setRoleDescription(requestData.get("ROLE_DESCRIPTION"));
            role.setIsActive(requestData.get("IS_ACTIVE"));
            role.setCreatedDate(LocalDateTime.now());

            SmsaRole savedRole = smsaRoleRepository.save(role);
            logger.info("User role created: {}", savedRole.getRoleName());
            return savedRole;

        } catch (Exception e) {
            logger.error("Error creating user role: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create user role: " + e.getMessage());
        }
    }

    public SmsaUser creteUser(Map<String, String> requestData) {
        logger.info("Creating new user: {}", requestData.get("loginId"));

        try {
            SmsaUser user = new SmsaUser();
            user.setLoginId(requestData.get("loginId"));
            user.setUsername(requestData.get("username"));
            user.setEmail(requestData.get("email"));
            user.setFirstName(requestData.get("firstName"));
            user.setLastName(requestData.get("lastName"));
            user.setDepartment(requestData.get("department"));
            user.setBicAccessList(requestData.get("bicAccessList"));
            user.setIsActive(requestData.getOrDefault("isActive", "Y"));
            user.setCreatedDate(LocalDateTime.now());
            user.setPasswordChanged(LocalDateTime.now());
            user.setFailedLoginAttempts(0);
            user.setLastLogin(null);
            user.setAccountLockedUntil(null);
            user.setAccessToken(null);

            SmsaUser savedUser = userRepository.save(user);
            logger.info("User created successfully: {}", savedUser.getLoginId());
            return savedUser;

        } catch (Exception e) {
            logger.error("Error creating user: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create user: " + e.getMessage());
        }
    }

    public List<SmsaUser> getUsers() {
        return userRepository.findAll();

    }

    public ResponseEntity<String> logout(String encodeToken, String encodeDeviceHash) {
        logger.debug("Inside logout method");

        try {

            String token = decrypt(encodeToken);
            String deviceHash = decrypt(encodeDeviceHash);
            if (token == null || token.trim().isEmpty()) {
                logger.warn("Missing or empty Authorization token");
                return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
            }

            logger.info("Token received for logout");

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String loginId = claims.getId();
            logger.debug("Parsed loginId from token: {}", loginId);
            UserSessionToken userSessionToken = userSessionTokenRepository.findByTokenAndDeviceHash(token, deviceHash);
            if (userSessionToken.getToken() == null || userSessionToken.getStatus().equals(false)) {
                return new ResponseEntity<>("Already logged out.", HttpStatus.NOT_FOUND);
            }
            userSessionToken.setToken(null);
            userSessionToken.setStatus(false);
            userSessionTokenRepository.save(userSessionToken);

            SmsaUser data = getUserByLoginId(loginId);

            if (data == null) {
                logger.warn("No user found with loginId: {}", loginId);
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            if (data.getAccessToken() == null || data.getAccessToken().isEmpty()) {
                logger.warn("Access token is already null or empty for user: {}", loginId);
                throw new CustomException(SmsaErrorCodes.UN_AUTHORIZED, "Token invalid or user already logged out");
            }

            data.setAccessToken(null); // remove token
            userRepository.save(data);
            logger.info("User {} logged out successfully", loginId);

            return ResponseEntity.ok("Logout successful");

        } catch (JwtException jwtEx) {
            logger.error("JWT parsing failed: {}", jwtEx.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid JWT token");
        } catch (CustomException ce) {
            logger.error("CustomException during logout: {}", ce.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ce.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error during logout", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error during logout");
        }
    }

    public void validateUserDevice(AuthenticationRequest authenticationRequest, String token) {

        UserSessionToken userSessionTokenData = userSessionTokenRepository.findByUserIdAndDeviceHashAndStatusTrue(authenticationRequest.getUsername(), authenticationRequest.getDeviceHase());

        SmsaUser user = userRepository.findByLoginId(authenticationRequest.getUsername());


        if (userSessionTokenData == null) {
            UserSessionToken userSessionToken = new UserSessionToken();
            userSessionToken.setUserId(authenticationRequest.getUsername());
            userSessionToken.setDeviceHash(authenticationRequest.getDeviceHase());
            userSessionToken.setToken(token);
            userSessionToken.setStatus(true);
            userSessionToken.setLastLogin(LocalDateTime.now());
            userSessionTokenRepository.save(userSessionToken);
        } else {
            userSessionTokenData.setToken(user.getAccessToken());
            userSessionTokenRepository.save(userSessionTokenData);
        }
    }

    public void verifyValidateUserDevice(String token, String newAccessToken, String deviceHash) {

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        String loginId = claims.getId();
        UserSessionToken userSessionTokenData = userSessionTokenRepository.findByUserIdAndDeviceHashAndStatusTrue(loginId, deviceHash);

        if (userSessionTokenData == null) {
            throw new JwtException("Token Device token and hash ");
        }
        if (userSessionTokenData.getToken() == null) {
            throw new JwtException("Please login token and hash expire.");
        }

        userSessionTokenData.setToken(newAccessToken);
        userSessionTokenRepository.save(userSessionTokenData);

    }

    public String userLoginDetails(String encryptedToken) {
        try {
            String token = decrypt(encryptedToken); // decrypt the encrypted token
            logger.info("Decrypted token: {}", token);

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String loginId = claims.getId();

            List<UserSessionToken> sessionData = userSessionTokenRepository.findByUserIdOrderByLastLoginDesc(loginId);

            if (sessionData == null || sessionData.isEmpty()) {
                throw new RuntimeException("No session data found for user: " + loginId);
            }

            // If more than one session, get the previous login
            int index = sessionData.size() >= 2 ? 1 : 0;
            UserSessionToken session = sessionData.get(index);

            UserLoginDetailsResponse response = new UserLoginDetailsResponse(
                    session.getUserId(),
                    session.getLastLogin()
            );

            // Convert to JSON
            String json = objectMapper.writeValueAsString(response);

            // Encrypt and return
            return encrypt(json);

        } catch (Exception e) {
            logger.error("Failed to process login details", e);
            throw new RuntimeException("Unable to retrieve login details", e);
        }
    }


    public String encrypt(String data) {
        try {
            // 16-byte key for AES-128
            SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), "AES");

            // Use the same fixed IV as decryption (NOT secure for real systems)
            byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);  // 16 bytes
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

            // Encode result to Base64
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            return "";
        }
    }

    public String decrypt(String encryptedAcc) {
        try {
            // 16-byte key for AES-128
            SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), "AES");

            // Example: fixed IV (not secure for production use)
            byte[] ivBytes = iv.getBytes(StandardCharsets.UTF_8);  // 16 bytes
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedAcc));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
}
