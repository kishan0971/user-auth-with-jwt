package com.blog.service.externalServices;

import com.blog.repository.DTO.BlogCreationFeignClient;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Map;

@FeignClient(name = "blog-service", url = "http://localhost:8080")
public interface ExternalBlogService {

    @PostMapping(path = "/in2it-blog/posts")
    Map<String,Object> postBlog(BlogCreationFeignClient blogCreationFeignClient);
}

