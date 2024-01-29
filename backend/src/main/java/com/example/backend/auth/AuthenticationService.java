package com.example.backend.auth;

import com.example.backend.dto.UserDto;
import com.example.backend.entities.User;
import com.example.backend.jwtUtility.JwtUtil;
import com.example.backend.mapper.UserDTOMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * Service class for managing authentication.
 */
@Service
public class AuthenticationService {
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserDTOMapper userDTOMapper;

    /**
     * Constructor for the AuthenticationService class.
     * @param jwtUtil The JwtUtil.
     * @param authenticationManager The AuthenticationManager.
     * @param userDTOMapper The UserDTOMapper.
     */
    public AuthenticationService(JwtUtil jwtUtil, AuthenticationManager authenticationManager, UserDTOMapper userDTOMapper) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.userDTOMapper = userDTOMapper;
    }

    /**
     * Login a user.
     * @param authenticationRequest The user to login.
     * @return The logged in user.
     */
    public AuthenticationResponse login(AuthenticationRequest authenticationRequest) {
        return getAuthenticationResponse(authenticationRequest);
    }

    /**
     * Get the authentication response.
     * @param authenticationRequest The authentication request.
     * @return The authentication response.
     */
    private AuthenticationResponse getAuthenticationResponse(AuthenticationRequest authenticationRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.email(),
                        authenticationRequest.password()
                )
        );
        User user = (User) authentication.getPrincipal();
        UserDto userDto = userDTOMapper.apply(user);
        String jwt = jwtUtil.generateToken(userDto, userDto.getRoles());
        return new AuthenticationResponse(jwt, userDto);
    }
}