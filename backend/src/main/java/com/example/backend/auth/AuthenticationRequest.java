package com.example.backend.auth;

public record AuthenticationRequest(
        String email,
        String password
){}
