package com.example.backend.service;


import com.example.backend.dao.PostRepository;
import com.example.backend.dto.PostDto;
import com.example.backend.dto.PostsDto;
import com.example.backend.dto.UserDto;
import com.example.backend.dto.UserDtoPost;
import com.example.backend.entities.Posts;
import com.example.backend.exception.HandleMethodArgumentNotValid;
import com.example.backend.exception.ResourceNotFoundException;
import com.example.backend.mapper.PostDtoMapper;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class PostService {

    private final PostRepository postRepository;
    private final PostDtoMapper postDtoMapper;
    private final UserService userService;


    public PostService(PostRepository postRepository, PostDtoMapper postDtoMapper, UserService userService) {
        this.postRepository = postRepository;
        this.postDtoMapper = postDtoMapper;
        this.userService = userService;
    }

//    Create new post
    public PostDto createPost(PostDto postsDto, UserDtoPost user) {
        var author = userService.getUserByEmail(user.email());

//     var author = userService.getUserByEmail(user.getEmail());
        var post = new Posts();
        post.setAuthor(author);
        post.setTitle(postsDto.getTitle());
        post.setContent(postsDto.getContent());
        post.setCreatedAt(LocalDateTime.now());
        return postDtoMapper.apply(postRepository.save(post));

    }


//    Get all posts
    public List<PostDto> getAllPosts() {
        try{
           return postRepository.findAll().stream()
                    .map(postDtoMapper)// Using method reference to apply PostDtoMapper
                    .collect(Collectors.toList());

        }catch (Exception e){
         throw new RuntimeException("Try again with permission as Admin");
        }
    }


//      delete by id
    public void deletePost(UUID id) {
        Optional<Posts> optionalPosts = postRepository.findById(id);
        if (optionalPosts.isPresent()) {
            postRepository.deleteById(id);
        } else {
            // Handle the case where the user with the specified ID is not found
            throw new HandleMethodArgumentNotValid("Post not found with ID: " + id);
        }
    }

    //  Find by id
    public PostDto getPostById(UUID id) {
        Optional<Posts> post = postRepository.findById(id);
        if (post.isPresent()) {
            var po = postDtoMapper.apply(post.get());
            System.out.println("maper❌   " +  po);
            return po;
        } else {
            throw new ResourceNotFoundException("User not found with ID: " + id);
        }
    }


    public PostDto updatePost(UUID id, PostsDto postsDto) {
        Posts posts = postRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + id));
            boolean updated = false;

            if (postsDto.getTitle() != null && !postsDto.getTitle().equals(posts.getTitle())) {
                posts.setTitle(postsDto.getTitle());
                updated = true;
            }

            if (postsDto.getContent() != null && !postsDto.getContent().equals(posts.getContent()) ) {
                posts.setContent(postsDto.getContent());
                updated = true;
            }  if (!updated) {
                throw new RuntimeException("No changes ware made ");
          }
          Posts postUpdate =  postRepository.save(posts);
        System.out.println(postUpdate);
          return postDtoMapper.apply(postUpdate);

    }
}
