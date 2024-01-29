package com.example.backend.dto;


import com.example.backend.entities.Roles;
//import jakarta.validation.constraints.Email;
//import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.*;
import org.hibernate.validator.constraints.Range;

import java.util.List;


@Data
public class UserRegistrationDTO {
    @NotBlank(message = "Name is required")
    private String name;
    @NotBlank(message = "Email is required")
        @NotNull.List({
        @NotNull(message = "Email cannot be null"),
        @NotNull(message = "Email cannot be empty")
    })
    @Email(message = "Email should be valid")
    @Pattern(regexp = "^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", message = "Email should be valid")
    private String email;
    @NotBlank(message = "Password is required")
    //    validate password
    @NotNull.List({
        @NotNull(message = "Password cannot be null"),
        @NotNull(message = "Password cannot be empty")
    })
    @Range(min = 3, max = 26, message = "Password must be between 8 and 20 characters")
//    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).*$", message = "Password must contain at least one uppercase letter, one lowercase letter and one number")
    private String password;


    private String username;


    private List<String> roles;


    public UserRegistrationDTO() {
    }

    @Override
    public String toString() {
        return "UserRegistrationDTO{" +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", roles=" + roles +
                ", username='" + username + '\'' +
                '}';
    }
}
