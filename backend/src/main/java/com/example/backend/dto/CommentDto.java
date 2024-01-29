package com.example.backend.dto;

import com.example.backend.entities.Comments;
import com.example.backend.entities.Likes;
import lombok.Data;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@ToString
public class CommentDto{
    public UUID id;
    public LocalDateTime createAt;
    public String comment;
    public UserDtoPost user;


    public CommentDto(UUID id, LocalDateTime date, String comment, UserDtoPost userDto) {
        this.id = id;
        this.createAt = date;
        this.comment = comment;
        this.user = userDto;
    }
}


