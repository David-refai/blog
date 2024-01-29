package com.example.backend.controller;

import com.example.backend.entities.Likes;
import com.example.backend.exception.UserAlreadyLikedException;
import com.example.backend.service.LikesService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/likes")
public class LikeController {


    private final LikesService likesService;

    public LikeController(LikesService likesService) {
        this.likesService = likesService;
    }

    @PostMapping("/like")
    public ResponseEntity<?> likePost(@RequestParam UUID userId, @RequestParam UUID postId) {
        try {
            Likes like = likesService.likePost(userId, postId);
            return ResponseEntity.ok(like);
        } catch (UserAlreadyLikedException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
}


