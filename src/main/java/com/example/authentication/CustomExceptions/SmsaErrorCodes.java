/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Enum.java to edit this template
 */
package com.example.authentication.CustomExceptions;

/**
 *
 * @author abcom
 */
public enum SmsaErrorCodes {

    SERVER_ERROR("401", "Invalid username or password"),
    UN_AUTHORIZED("401", "Invalid or expired token"),
    NO_RECORD_FOUND("403", "Access denied"),
    INVALID_REQUEST("400", "invalid input passed"),
    INTERNAL_SERVER_ERROR("501", "Could not process the request");


    private final String code;
    private final String description;

    SmsaErrorCodes(String code, String description) {
        this.code = code;
        this.description = description;
    }
    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}
