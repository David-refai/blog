package com.example.backend.service;


import com.example.backend.dao.RoleRepository;
import com.example.backend.dao.UserRepository;
import com.example.backend.dto.UserDto;
import com.example.backend.dto.UserRegistrationDTO;
import com.example.backend.entities.Roles;
import com.example.backend.entities.User;
import com.example.backend.exception.ExistsEmailException;
import com.example.backend.exception.HandleMethodArgumentNotValid;
import com.example.backend.exception.ResourceNotFoundException;
import com.example.backend.mapper.UserDTOMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;


/**
 * Service class for managing users.
 */

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    private final UserDTOMapper userDTOMapper;

    @Autowired
    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       RoleRepository roleRepository, UserDTOMapper userDTOMapper) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userDTOMapper = userDTOMapper;
    }




    /**
     * Save a new user.
     *
     * @param userRegistrationDTO The user to save.
     * @return The saved user.
     */


    public UserDto saveUserWithRoles(UserRegistrationDTO userRegistrationDTO) {
// Validate the UserDto (e.g., check for required fields)
        validateUserDto(userRegistrationDTO);

//        check if email already exists
        existsByEmail(userRegistrationDTO.getEmail());

        User user = new User();
        user.setName(userRegistrationDTO.getName());
        user.setEmail(userRegistrationDTO.getEmail());
        user.setPassword(passwordEncoder.encode(userRegistrationDTO.getPassword()));
        user.setCreatedAt(LocalDateTime.now());


        if (userRegistrationDTO.getRoles() == null) {
            userRegistrationDTO.setRoles(List.of("USER"));
        }

        var roles = userRegistrationDTO.getRoles();
        roles.forEach(roleName -> {
            Roles role = new Roles();
            role.setName(roleName);
            role.setUser(user);
            roleRepository.save(role);
            user.addRole(role);
        });

        User savedUser = userRepository.save(user);
       return  userDTOMapper.apply(savedUser);
    }


    /**
     * Get all users.
     * @return A list of all users.
     */
    public List<UserDto> getAllUsers() {

        return userRepository.findAll().stream()
                .map(userDTOMapper)
                .collect(Collectors.toList());

    }

    /**
     * Get the user with the specified ID.
     * @param id The ID of the user to get.
     * @return The user with the specified ID.
     * @throws ResourceNotFoundException if the user is not found.
     */

    public UserDto getUserById(UUID id) {
        Optional<User> user = userRepository.findById(id);
        if (user.isPresent()) {
            return userDTOMapper.apply(user.get());
        } else {
            throw new ResourceNotFoundException("User not found with ID: " + id);
        }
    }


    /**
     * Check if the specified email address already exists.
     *
     * @param email The email address to check.
     */
    public void existsByEmail(String email) {
    userRepository.getByEmail(email)
                .ifPresent(user -> {
                    throw new ExistsEmailException("Email already exists");
                });
    }

    /**
     * Validate the UserDto (e.g., check for required fields)
     * @param user The UserDto to validate.
     * @throws HandleMethodArgumentNotValid if the UserDto is invalid.
      */
    private void validateUserDto( UserRegistrationDTO user) {
        if (user.getName() == null || user.getName().isEmpty()) {
            throw new HandleMethodArgumentNotValid("Name is required");
        }
        if (user.getEmail() == null || user.getEmail().isEmpty()) {
            throw new HandleMethodArgumentNotValid("Email is required");
        }
        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            throw new HandleMethodArgumentNotValid("Password is required");
        }

    }

    public User getUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    public User getUserByEmail(String token) {
        return userRepository.getByEmail(token)
                        .orElseThrow(() ->
                                new ResourceNotFoundException("User not found with email: " + token));
    }

    public void deleteUser(UUID id) {
        User user = userRepository.findById(id)
             .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + id));
        userRepository.delete(user);
    }


    /**
     * Update the user with the specified ID.
     * @param id The ID of the user to update.
     * @param userRegistrationRequest The updated user information.
     * @return The updated user.
     * @throws ResourceNotFoundException if the user is not found.
     * @throws ExistsEmailException if the email already exists.
     *
     */
//    public UserDto updateUser (Long id, UserRegistrationDTO userRegistrationRequest) {
//        User user = userRepository.findById(id)
//                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + id));
//
//            boolean updated = false;
//
//            if (userRegistrationRequest.getName() != null && !userRegistrationRequest.getName().equals(user.getName())) {
//                user.setName(userRegistrationRequest.getName());
//                updated = true;
//            }
//            // Check if a new password is provided
//            if (userRegistrationRequest.getPassword() != null && !userRegistrationRequest.getPassword().isEmpty()) {
////                updatePassword(user.getEmail(), userRegistrationRequest.getPassword());
//                user.setPassword(passwordEncoder.encode(userRegistrationRequest.getPassword()));
//                updated = true;
//            }
//
//            // Check if a new role is provided
////            if (userRegistrationRequest.getRoles() != null && !userRegistrationRequest.getRoles().isEmpty()) {
////                user.setRole(userRegistrationRequest.getRoles().stream().map(Roles::new).collect(Collectors.toList()));
////                updated = true;
////            }
//
//            // Check if a new email is provided
//            if (userRegistrationRequest.getEmail() != null && !userRegistrationRequest.getEmail().equals(user.getEmail())) {
//                existsByEmail(userRegistrationRequest.getEmail());
//                user.setEmail(userRegistrationRequest.getEmail());
//                updated = true;
//            }else if(userRegistrationRequest.getEmail().equals(user.getEmail())){
//                updated = true;
//            }
//            if (!updated) {
//                throw new ExistsEmailException("No changes were made");
//            }
//
//
//          User userUpdate =  userRepository.save(user);
//        System.out.println(userUpdate);
//          return userDTOMapper.apply(userUpdate);
//
//    }

    /**
     * Delete the user with the specified ID.
     * @param id The ID of the user to delete.
     * @return The deleted user.
     * @throws ResourceNotFoundException if the user is not found.
     */
//    public Optional<User> deleteUser(Long id) {
//        Optional<User> optionalUser = userRepository.findById(id);
//        if (optionalUser.isPresent()) {
//            userRepository.deleteById(id);
//            return optionalUser;
//        } else {
//            // Handle the case where the user with the specified ID is not found
//            throw new HandleMethodArgumentNotValid("User not found with ID: " + id);
//        }
//    }


}
