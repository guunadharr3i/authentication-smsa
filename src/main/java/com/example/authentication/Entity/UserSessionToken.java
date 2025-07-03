/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.authentication.Entity;

/**
 * @author abcom
 */


import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_session_tokens")
public class UserSessionToken {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_session_tokens_seq")
    @SequenceGenerator(name = "user_session_tokens_seq", sequenceName = "user_session_tokens_seq", allocationSize = 1)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "device_hash", unique = true, nullable = false)
    private String deviceHash;

    @Column(unique = true)
    private String token;

    @Column(nullable = false)
    private Boolean status;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    // Constructors
    public UserSessionToken() {
    }

    public UserSessionToken(String userId, String deviceHash, String token, Boolean status, LocalDateTime lastLogin) {
        this.userId = userId;
        this.deviceHash = deviceHash;
        this.token = token;
        this.status = status;
        this.lastLogin = lastLogin;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getDeviceHash() {
        return deviceHash;
    }

    public void setDeviceHash(String deviceHash) {
        this.deviceHash = deviceHash;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Boolean getStatus() {
        return status;
    }

    public void setStatus(Boolean status) {
        this.status = status;
    }

    public LocalDateTime getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }

}
