package com.example.backend.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.NOT_FOUND)
public class NotFoundFileException extends RuntimeException{
    public NotFoundFileException(String message) {
        super(message);
    }
}
