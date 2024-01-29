package com.example.backend.mapper;


import com.example.backend.dto.PostsDto;
import com.example.backend.dto.UserDto;
import com.example.backend.entities.Comments;
import com.example.backend.entities.Posts;
import com.example.backend.entities.User;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;


/**
 * Mapper class for mapping User to UserDto.
 * @see User
 * @see UserDto
 * @see Function
 * @see GrantedAuthority
 */
@Service
public class UserDTOMapper implements Function<User, UserDto> {


    @Override
    public UserDto apply(User user) {
        return new UserDto(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getPosts(),
                user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()),
                user.getUsername(),
                user.getCreatedAt()
        );
    }




}
