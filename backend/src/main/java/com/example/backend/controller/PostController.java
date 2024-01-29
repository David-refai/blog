package com.example.backend.controller;


import com.example.backend.dto.PostDto;
import com.example.backend.dto.PostsDto;
import com.example.backend.dto.UserDto;
import com.example.backend.dto.UserDtoPost;
import com.example.backend.entities.Posts;
import com.example.backend.entities.User;
import com.example.backend.jwtUtility.JwtUtil;
import com.example.backend.mapper.UserDTOMapper;
import com.example.backend.service.PostService;
import com.example.backend.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/posts")
public class PostController {

    private final PostService postService;
    private final JwtUtil jwtUtil;
    private final UserDTOMapper userDTOMapper;

    private final UserService userService;

    public PostController(PostService postService, JwtUtil jwtUtil, UserDTOMapper userDTOMapper, UserService userService) {
        this.postService = postService;
        this.jwtUtil = jwtUtil;
        this.userDTOMapper = userDTOMapper;
        this.userService = userService;
    }

    @GetMapping("/all")
    public List<PostDto> allPosts(){
        return postService.getAllPosts();
    }


    @PostMapping("/create-post")
    public ResponseEntity<PostDto> createPost(@RequestHeader("Authorization") String authorizationHeader,
                                            @RequestBody PostDto postsDto) {
//        System.out.println("postsDto: " + postsDto);
        try {
            String token = authorizationHeader.substring(7);
//
            if (jwtUtil.validateToken(token)) {
                String userEmail = jwtUtil.getSubject(token);
                User user = userService.getUserByEmail(userEmail);

                var userDtoPost = new UserDtoPost(user.getId(), user.getName(), user.getEmail());
                // Check if the user has the required authority

                var post = postService.createPost(postsDto, userDtoPost);
                return ResponseEntity.ok(post);
            }
            else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

//    delete post by id
    @DeleteMapping("/delete-post/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable UUID id) {
        postService.deletePost(id);
        return ResponseEntity.ok().build();
    }

//     find post by id
    @GetMapping("/{id}")
    public ResponseEntity<PostDto> getUserById(@PathVariable UUID id) {
        var postById = postService.getPostById(id);
        return ResponseEntity.ok(postById);
    }

@PutMapping("/{id}")
    public RequestEntity<?> updatePost(@PathVariable UUID id, @RequestBody PostsDto postsDto){
        var postIds = postService.updatePost(id, postsDto);
        return (RequestEntity<?>) ResponseEntity.status(HttpStatus.OK);
}

}
