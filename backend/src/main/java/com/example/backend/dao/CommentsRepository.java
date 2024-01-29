package com.example.backend.dao;

import com.example.backend.dto.UserDto;
import com.example.backend.entities.Comments;
import com.example.backend.entities.Posts;
import com.example.backend.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.UUID;

public interface CommentsRepository extends JpaRepository<Comments, UUID> {

}