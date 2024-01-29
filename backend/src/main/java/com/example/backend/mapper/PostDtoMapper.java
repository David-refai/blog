package com.example.backend.mapper;


import com.example.backend.dto.*;
import com.example.backend.entities.Posts;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;


@Service
public class PostDtoMapper implements Function<Posts, PostDto>  {

    private final UserDTOMapper userDTOMapper;

    public PostDtoMapper(UserDTOMapper userDTOMapper) {
        this.userDTOMapper = userDTOMapper;
    }

    @Override
        public PostDto apply(Posts post) {
        var user = new UserDtoPost(
                post.getAuthor().getId(),
                post.getAuthor().getName(),
                post.getAuthor().getEmail()
        );

         List<CommentDto> commentsDto = new ArrayList<CommentDto>();
         for (var comment : post.getComments()) {
             commentsDto.add(new CommentDto(
                     comment.getId(),
                     comment.getDate(),
                     comment.getComment(),
                    user
             ));
         }

        return new PostDto(
                post.getId(),
                post.getTitle(),
                post.getContent(),
                post.getCreatedAt(),
                user,
                commentsDto,
                post.getLikes()

        );
    }
}
