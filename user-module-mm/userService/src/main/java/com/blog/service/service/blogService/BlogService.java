package com.blog.service.service.blogService;

import com.blog.repository.DTO.BlogCreationRequest;

import java.io.IOException;
import java.util.Map;

public interface BlogService {
    Map<String, Object> createBlog(String creator, BlogCreationRequest blogCreationRequest) throws IOException;
}
