package com.example.backend.mapper;

import com.example.backend.dto.CommentDto;
import com.example.backend.dto.UserDto;
import com.example.backend.dto.UserDtoPost;
import com.example.backend.entities.Comments;
import com.example.backend.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;


@Service
public class CommentsDtoMapper implements Function<Comments, CommentDto> {


    @Override
    public CommentDto apply(Comments comments) {
        User user = comments.getUser();
        UserDtoPost userDto = new UserDtoPost(
                user.getId(),
                user.getName(),
                user.getEmail()
        );
        return new CommentDto(
                comments.getId(),
                comments.getDate(),
                comments.getComment(),
                userDto


        );
    }
}
