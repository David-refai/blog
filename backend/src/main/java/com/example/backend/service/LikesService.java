package com.example.backend.service;

import com.example.backend.dao.LikesRepository;
import com.example.backend.dao.PostRepository;
import com.example.backend.dao.UserRepository;
import com.example.backend.entities.Likes;
import com.example.backend.entities.Posts;
import com.example.backend.entities.User;
import com.example.backend.exception.ResourceNotFoundException;
import com.example.backend.exception.UserAlreadyLikedException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class LikesService {


    private final LikesRepository likesRepository;


    private final UserRepository userRepository;
    private final PostRepository postRepository;

    public LikesService(LikesRepository likesRepository,
                        UserRepository userRepository,
                        PostRepository postRepository) {
        this.likesRepository = likesRepository;
        this.userRepository = userRepository;
        this.postRepository = postRepository;
    }

    public Likes likePost(UUID userId, UUID postId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User Not Found with this ID " + userId));
        Posts post = postRepository.findById(postId)
                .orElseThrow(() -> new ResourceNotFoundException("Post Not Found with this ID " + postId));

        if (user != null && post != null) {
            Likes existingLike = likesRepository.findByUserAndPost(user, post);

            if (existingLike == null) {
                Likes like = Likes.builder()
                        .like("Liked")
                        .user(user)
                        .post(post)
                        .build();

                return likesRepository.save(like);
            } else {
                throw new UserAlreadyLikedException("User already liked the post");
            }
        } else {
            throw new IllegalArgumentException("User or post does not exist");
        }
    }
}
