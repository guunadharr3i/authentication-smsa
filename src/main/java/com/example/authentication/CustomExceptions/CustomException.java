/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.authentication.CustomExceptions;

/**
 *
 * @author abcom
 */
public class CustomException extends RuntimeException {

    private final SmsaErrorCodes errorCode;
    private final String errorMessage;

    public CustomException(SmsaErrorCodes errorCode, String errorMessage) {
        super(errorMessage);
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }
}
