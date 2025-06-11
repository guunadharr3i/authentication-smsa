package com.example.authentication.service;

import com.example.authentication.Repo.SmsaRoleRepository;
import com.example.authentication.Repo.UserRepository;
import com.example.authentication.Entity.SmsaRole;
import com.example.authentication.Entity.SmsaUser;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Map;

import io.jsonwebtoken.*;

@Service
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final SmsaRoleRepository smsaRoleRepository;
    private static final String SECRET_KEY = "mySuperSecureSecretKeyThatIsAtLeast32Bytes!"; // use env variable in real apps
    private static final long EXPIRATION_TIME = 10 * 60 * 3000; // 10 minutes in milliseconds
    private static final long REFRESH_TOKEN_EXPIRATION = 7 * 24 * 60 * 60 * 1000; // 7 days

    public AuthenticationService(UserRepository userRepository, SmsaRoleRepository smsaRoleRepository) {
        this.userRepository = userRepository;
        this.smsaRoleRepository = smsaRoleRepository;
    }

    public SmsaUser getUserByLoginId(String loginId) {

        if (loginId == null || loginId.trim().isEmpty()) {
            throw new IllegalArgumentException("username must not be null or empty.");
        }
        SmsaUser user = userRepository.findByLoginId(loginId);
        if (user == null) {
            throw new RuntimeException("username not found for login " + loginId);
        }
        generateAccessToken(user);
        user.setAccessToken(generateAccessToken(user));
        return userRepository.save(user);
    }

    private static Key getSigningKey() {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    public String generateAccessToken(SmsaUser userData) {
        return Jwts.builder()
                .setSubject("access")
                .setIssuedAt(new Date())
                .setId(userData.getLoginId())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken() {
        return Jwts.builder()
                .setSubject("refresh")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String validateToken(String token) throws JwtException {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String loginId = claims.getId(); // Extracting loginId from old token

            if (loginId == null || loginId.isEmpty()) {
                throw new JwtException("Token does not contain a valid login ID");
            }

            // Generate and return new token using the same loginId
            String newJwt = Jwts.builder()
                    .setSubject("access")
                    .setId(loginId)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                    .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                    .compact();
            SmsaUser data = getUserByLoginId(loginId);
            data.setAccessToken(newJwt);
            userRepository.save(data);
            return newJwt;

        } catch (JwtException e) {
            throw new JwtException("Token validation failed: " + e.getMessage());
        }
    }

    public SmsaRole creteUserRoleData(Map<String, String> requestDat) {

        SmsaRole role = new SmsaRole();
        role.setRoleName(requestDat.get("ROLE_NAME"));
        role.setRoleDescription(requestDat.get("ROLE_DESCRIPTION"));
        role.setIsActive(requestDat.get("IS_ACTIVE"));
        role.setCreatedDate(LocalDateTime.now());
        return smsaRoleRepository.save(role);
    }

}
