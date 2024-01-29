package com.example.backend.dto;

import com.example.backend.entities.Comments;
import com.example.backend.entities.Likes;
import com.example.backend.entities.User;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
@Data
@ToString
public class PostsDto{

    private UUID id;

    private String title;

    private String content;

    private LocalDateTime createAt;

    private User author;


    private List<Comments> comments;

    private List<Likes> likes;

 public PostsDto(UUID id, String title, String content, LocalDateTime createAt, User author, List<Comments> comments, List<Likes> likes) {
  this.id = id;
  this.title = title;
  this.content = content;
  this.createAt = createAt;
  this.author = author;
  this.comments = comments;
  this.likes = likes;
 }


 public PostsDto(UUID id, String title, String content, LocalDateTime createdAt) {
  this.id = id;
  this.title = title;
  this.content = content;
  this.createAt = createdAt;
 }

}




