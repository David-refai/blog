package com.example.backend.controller;


import com.example.backend.dao.UserRepository;
import com.example.backend.dto.UserDto;
import com.example.backend.dto.UserRegistrationDTO;
import com.example.backend.entities.User;
import com.example.backend.jwtUtility.JwtUtil;
import com.example.backend.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserService userService;
    private final JwtUtil jwtTokenService;

    private UserRepository userRepository;

    public UserController(UserService userService, JwtUtil jwtTokenService) {
        this.userService = userService;
        this.jwtTokenService = jwtTokenService;
    }



//    @GetMapping("/user/{id}")
//    public ResponseEntity<UserDto> getUserById(@PathVariable Long id) {
//        var userById = userService.getUserById(id);
//        return ResponseEntity.ok(userById);
//    }
//
//    @PutMapping("/update-user/{id}")
//    public ResponseEntity<UserDto> updateUser(@PathVariable Long id, @RequestBody UserRegistrationDTO userDto) {
//        userService.updateUser(id, userDto);
//        return ResponseEntity.ok().build();
//    }
//
    @DeleteMapping("/delete-user/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable UUID id) {
        userService.deleteUser(id);
        return ResponseEntity.ok().build();
    }
//
    @GetMapping("/{id}")
    public ResponseEntity<?> getUserById(@PathVariable UUID id) {
        var userById = userService.getUserById(id);
        return ResponseEntity.ok(userById);
    }

//    all users
@GetMapping("/all")
public ResponseEntity<List<UserDto>> getAllUsers(){
    var users = userService.getAllUsers();
    return ResponseEntity.ok(users);
}


}