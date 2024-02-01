package com.example.backend.auth;

import com.example.backend.dto.UserDto;
public record AuthenticationResponse(
        String jwt,
        UserDto user

){}
