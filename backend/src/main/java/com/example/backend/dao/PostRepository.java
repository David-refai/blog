package com.example.backend.dao;

import com.example.backend.entities.Posts;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;


@Repository
public interface PostRepository extends JpaRepository<Posts, UUID> {
}
