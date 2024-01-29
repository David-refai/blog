package com.example.backend.controller;

import com.example.backend.dto.CommentDto;
import com.example.backend.dto.UserDtoPost;
import com.example.backend.entities.User;
import com.example.backend.jwtUtility.JwtUtil;
import com.example.backend.mapper.UserDTOMapper;
import com.example.backend.service.CommentService;
import com.example.backend.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/comments")
public class CommentController {

    private final CommentService commentService;
    private final JwtUtil jwtUtil;
    private final UserService userService;

    public CommentController(CommentService commentService, JwtUtil jwtUtil, UserService userService) {
        this.commentService = commentService;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }







    @GetMapping
    public List<CommentDto> allComments() {
        return commentService.getAllComments();
    }


    @PostMapping("/create-comment/{postId}")
    public ResponseEntity<CommentDto> createPost(@RequestHeader("Authorization")
                                               String authorizationHeader,
                                                 @RequestBody CommentDto commentDto,
                                                 @PathVariable String postId) {


        System.out.println("authorizationHeader: " + authorizationHeader);
        String token = authorizationHeader.substring(7);

        if (jwtUtil.validateToken(token)) {
            String userEmail = jwtUtil.getSubject(token);
            User user = userService.getUserByEmail(userEmail);
            System.out.println(user);
            var userDtoPost = new UserDtoPost(user.getId(), user.getName(), user.getEmail());

            var comments = commentService.createComment(commentDto, userDtoPost, UUID.fromString(postId));
            return ResponseEntity.ok(comments);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

    }

    //
//    //    delete post by id
    @DeleteMapping("/delete-comment/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable UUID id) {
        commentService.deleteComment(id);
        return ResponseEntity.ok().build();
    }
//
//    //     find post by id
    @GetMapping("/{id}")
    public CommentDto getComments(@PathVariable UUID id) {
        return commentService.getPostById(id);
    }
//
//    @PutMapping("/{id}")
//    public RequestEntity<?> updatePost(@PathVariable UUID id, @RequestBody PostsDto postsDto){
//        var postIds = postService.updatePost(id, postsDto);
//        return (RequestEntity<?>) ResponseEntity.status(HttpStatus.OK);
//    }
}