package com.example.backend.dto;

import com.example.backend.entities.Comments;
import com.example.backend.entities.Likes;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
@Getter
@Setter
public class PostDto {
    @JsonProperty("postId")
    private UUID id;

    @JsonProperty("postTitle")
    private String title;

    @JsonProperty("postContent")
    private String content;

    @JsonProperty("createdAt")
    private LocalDateTime createAt;

    @JsonProperty("authorInfo")
    private UserDtoPost author;
//
    @JsonProperty("postComments")
    private List<CommentDto> comments;

    @JsonProperty("postLikes")
    private List<Likes> likes;

    public PostDto(UUID id, String title, String content, LocalDateTime createAt, UserDtoPost author, List<CommentDto> comments, List<Likes> likes) {
        this.id = id;
        this.title = title;
        this.content = content;
        this.createAt = createAt;
        this.author = author;
        this.comments = comments;
        this.likes = likes;
    }


//    public PostDto(UUID id, String title, String content, LocalDateTime createdAt, UserDtoPost author) {
//        this.id = id;
//        this.title = title;
//        this.content = content;
//        this.createAt = createdAt;
//        this.author = author;
//    }

    @Override
    public String toString() {
        return "PostDto{" +
                "id=" + id +
                ", title='" + title + '\'' +
                ", content='" + content + '\'' +
                ", createAt=" + createAt +
                ", author=" + author +
                ", comments=" + comments +
                ", likes=" + likes +
                '}';
    }
}
