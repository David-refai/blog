package com.example.backend.dto;

import com.example.backend.entities.Posts;
import com.example.backend.entities.Roles;
import lombok.*;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;


@Data
//@ToString
//@Builder
public class UserDto {

    private UUID id;
    private String name;
    private String email;
    private List<String> roles;
    private String username;
    private LocalDateTime createdAt;
    private List<Posts> posts;
    private List<CommentDto> comments;

    public UserDto(UUID id, String name, String email, List<Posts> collect, List<String> collect1, String username, LocalDateTime createdAt) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.posts = collect;
        this.roles = collect1;
        this.username = username;
        this.createdAt = createdAt;
    }


    }
