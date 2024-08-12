package com.blog.controller.controller;

import com.blog.controller.response.ResponseHandler;
import com.blog.repository.DTO.BlogCreationRequest;
import com.blog.service.service.blogService.BlogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.*;

@RestController
@RequestMapping("/in2it/blogs")
public class BlogController {

    @Autowired
    private BlogService blogService;

    @PostMapping("/create")
    public ResponseEntity<Object> createBlog(@ModelAttribute  BlogCreationRequest blogCreationRequest) throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();
        Map<String, Object> blog = blogService.createBlog(userName, blogCreationRequest);
        return ResponseHandler.responseBuilder("Blog Created SuccessFully", HttpStatus.OK,blog);
    }
}
