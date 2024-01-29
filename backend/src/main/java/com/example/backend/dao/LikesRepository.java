package com.example.backend.dao;

import com.example.backend.entities.Likes;
import com.example.backend.entities.Posts;
import com.example.backend.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface LikesRepository extends JpaRepository<Likes, UUID> {

    @Query("SELECT l FROM Likes l WHERE l.user = :user AND l.post = :post")
    Likes findByUserAndPost(@Param("user") User user, @Param("post") Posts post);
}
