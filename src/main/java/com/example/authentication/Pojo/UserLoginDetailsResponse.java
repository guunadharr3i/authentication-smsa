package com.example.authentication.Pojo;

import java.time.LocalDateTime;

public class UserLoginDetailsResponse {

    private String userId;
    private LocalDateTime lastLogin;

    public UserLoginDetailsResponse(String userId, LocalDateTime lastLogin) {
        this.userId = userId;
        this.lastLogin = lastLogin;
    }

    public String getUserId() {
        return userId;
    }

    public LocalDateTime getLastLogin() {
        return lastLogin;
    }
}
