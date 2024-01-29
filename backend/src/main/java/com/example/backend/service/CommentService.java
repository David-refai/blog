package com.example.backend.service;



import com.example.backend.dao.PostRepository;
import com.example.backend.dao.UserRepository;
import com.example.backend.dto.CommentDto;
import com.example.backend.dto.UserDtoPost;
import com.example.backend.entities.Comments;
import com.example.backend.dao.CommentsRepository;
import com.example.backend.exception.HandleMethodArgumentNotValid;
import com.example.backend.exception.ResourceNotFoundException;
import com.example.backend.exception.UnauthorizedAccessException;
import com.example.backend.mapper.CommentsDtoMapper;
import com.example.backend.mapper.PostDtoMapper;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class CommentService {

    private final UserService userService;
    private final PostService postService;
    private final PostRepository postRepository;
    private final CommentsRepository commentsRepository;
    private final CommentsDtoMapper commentDtoMapper;
    private final PostDtoMapper postDtoMapper;
    private final UserRepository userRepository;

    public CommentService(UserService userService, PostService postService, PostRepository postRepository,
                          CommentsRepository commentsRepository,
                          CommentsDtoMapper commentDtoMapper,
                          PostDtoMapper postDtoMapper,
                          UserRepository userRepository) {
        this.userService = userService;
        this.postService = postService;
        this.postRepository = postRepository;
        this.commentsRepository = commentsRepository;
        this.commentDtoMapper = commentDtoMapper;
        this.postDtoMapper = postDtoMapper;
        this.userRepository = userRepository;
    }


    //    Create new post
    public CommentDto createComment(CommentDto commentDto, UserDtoPost user, UUID postId) {
        // Validate if the user is allowed to comment on the post
//        if (isUserAllowedToComment(user, postId)) {
//            throw new UnauthorizedAccessException("User can not comment on this own post ❌");
//        }

        var author = userService.getUserByEmail(user.email());
        var post = postRepository.findById(postId)
                .orElseThrow(() -> new ResourceNotFoundException("Post not found with ID: " + postId));
        var comment = new Comments();
        comment.setId(commentDto.getId());
        comment.setUser(author);
        comment.setPost(post);
        comment.setComment(commentDto.getComment());
        comment.setDate(LocalDateTime.now());
        commentsRepository.save(comment);
        return commentDtoMapper.apply(comment);
    }

    private boolean isUserAllowedToComment(UserDtoPost user, UUID postId) {
        var post = postRepository.findById(postId)
                .orElseThrow(() -> new ResourceNotFoundException("Post not found with ID: " + postId));

        return user.id().equals(post.getAuthor().getId());
    }
    //    Get all posts
    public List<CommentDto> getAllComments() {
        try{
            return commentsRepository.findAll().stream()
                    .map(commentDtoMapper)// Using method reference to apply PostDtoMapper
                    .collect(Collectors.toList());

        }catch (Exception e){
            throw new RuntimeException("Try again with permission as Admin");
        }
    }


    //      delete by id
    public void deleteComment(UUID id) {
        Optional<Comments> optionalComments = commentsRepository.findById(id);
        if (optionalComments.isPresent()) {
            commentsRepository.deleteById(id);
        } else {
            // Handle the case where the user with the specified ID is not found
            throw new HandleMethodArgumentNotValid("Comment not found with ID: " + id);
        }
    }

    //  Find by id
    public void getCommentById(UUID id) {
        Optional<Comments> comment = commentsRepository.findById(id);
        if (comment.isPresent()) {
            commentDtoMapper.apply(comment.get());
        } else {
            throw new ResourceNotFoundException("Comment not found with ID: " + id);
        }
    }


    public CommentDto updateComment(UUID id, CommentDto commentDto) {
        Comments comment = commentsRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + id));
        boolean updated = false;

        if (commentDto.getComment() != null && !commentDto.getComment().equals(comment.getComment())) {
            comment.setComment(commentDto.getComment());
            updated = true;
        }  if (!updated) {
            throw new RuntimeException("No changes ware made ");
        }
        Comments commentUpdate = commentsRepository.save(comment);
        return commentDtoMapper.apply(commentUpdate);

    }

    public CommentDto getPostById(UUID id) {
        Optional<Comments> comment = commentsRepository.findById(id);
        if (comment.isPresent()) {
            return commentDtoMapper.apply(comment.get());
        } else {
            throw new ResourceNotFoundException("Comment not found with ID: " + id);
        }    }


}
