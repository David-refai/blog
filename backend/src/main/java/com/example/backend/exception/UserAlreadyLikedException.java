package com.example.backend.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class UserAlreadyLikedException extends RuntimeException {
    public UserAlreadyLikedException(String message) {
        super(message);
    }
}
