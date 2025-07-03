package com.example.authentication.Entity;

import java.io.Serializable;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "SMSA_USERS")
public class SmsaUser implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sms_user_seq")
    @SequenceGenerator(name = "sms_user_seq", sequenceName = "sms_user_seq", allocationSize = 1)
    @Column(name = "USER_ID")
    private Long userId;

    @Column(name = "USERNAME", unique = true, nullable = false)
    private String username;

    @Column(name = "LOGINID", unique = true, nullable = false)
    private String loginId;

    @Column(name = "EMAIL", unique = true, nullable = false)
    private String email;

    @Column(name = "FIRST_NAME")
    private String firstName;

    @Column(name = "LAST_NAME")
    private String lastName;

    @Column(name = "DEPARTMENT")
    private String department;

    @Column(name = "BIC_ACCESS_LIST")
    private String bicAccessList;

    @Column(name = "IS_ACTIVE")
    private String isActive;

    @Column(name = "ACCESS_TOKEN")
    private String accessToken;

    @Column(name = "CREATED_DATE")
    private LocalDateTime createdDate;

    @Column(name = "LAST_LOGIN")
    private LocalDateTime lastLogin;

    @Column(name = "PASSWORD_CHANGED")
    private LocalDateTime passwordChanged;

    @Column(name = "FAILED_LOGIN_ATTEMPTS")
    private Integer failedLoginAttempts;

    @Column(name = "ACCOUNT_LOCKED_UNTIL")
    private LocalDateTime accountLockedUntil;

    /**
     * @return the userId
     */
    public Long getUserId() {
        return userId;
    }

    /**
     * @param userId the userId to set
     */
    public void setUserId(Long userId) {
        this.userId = userId;
    }

    /**
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @param username the username to set
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return the loginId
     */
    public String getLoginId() {
        return loginId;
    }

    /**
     * @param loginId the loginId to set
     */
    public void setLoginId(String loginId) {
        this.loginId = loginId;
    }

    /**
     * @return the email
     */
    public String getEmail() {
        return email;
    }

    /**
     * @param email the email to set
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * @return the firstName
     */
    public String getFirstName() {
        return firstName;
    }

    /**
     * @param firstName the firstName to set
     */
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    /**
     * @return the lastName
     */
    public String getLastName() {
        return lastName;
    }

    /**
     * @param lastName the lastName to set
     */
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    /**
     * @return the department
     */
    public String getDepartment() {
        return department;
    }

    /**
     * @param department the department to set
     */
    public void setDepartment(String department) {
        this.department = department;
    }

    /**
     * @return the bicAccessList
     */
    public String getBicAccessList() {
        return bicAccessList;
    }

    /**
     * @param bicAccessList the bicAccessList to set
     */
    public void setBicAccessList(String bicAccessList) {
        this.bicAccessList = bicAccessList;
    }

    /**
     * @return the isActive
     */
    public String getIsActive() {
        return isActive;
    }

    /**
     * @param isActive the isActive to set
     */
    public void setIsActive(String isActive) {
        this.isActive = isActive;
    }

    /**
     * @return the accessToken
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * @param accessToken the accessToken to set
     */
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     * @return the createdDate
     */
    public LocalDateTime getCreatedDate() {
        return createdDate;
    }

    /**
     * @param createdDate the createdDate to set
     */
    public void setCreatedDate(LocalDateTime createdDate) {
        this.createdDate = createdDate;
    }

    /**
     * @return the lastLogin
     */
    public LocalDateTime getLastLogin() {
        return lastLogin;
    }

    /**
     * @param lastLogin the lastLogin to set
     */
    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }

    /**
     * @return the passwordChanged
     */
    public LocalDateTime getPasswordChanged() {
        return passwordChanged;
    }

    /**
     * @param passwordChanged the passwordChanged to set
     */
    public void setPasswordChanged(LocalDateTime passwordChanged) {
        this.passwordChanged = passwordChanged;
    }

    /**
     * @return the failedLoginAttempts
     */
    public Integer getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    /**
     * @param failedLoginAttempts the failedLoginAttempts to set
     */
    public void setFailedLoginAttempts(Integer failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    /**
     * @return the accountLockedUntil
     */
    public LocalDateTime getAccountLockedUntil() {
        return accountLockedUntil;
    }

    /**
     * @param accountLockedUntil the accountLockedUntil to set
     */
    public void setAccountLockedUntil(LocalDateTime accountLockedUntil) {
        this.accountLockedUntil = accountLockedUntil;
    }
}
