package com.example.backend.dto;

import java.util.UUID;

public record UserDtoPost(UUID id, String name, String email) {}
