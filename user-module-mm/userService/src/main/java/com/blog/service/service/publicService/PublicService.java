package com.blog.service.service.publicService;

import com.blog.repository.DTO.LoginRequest;

public interface PublicService {

    void loginService(LoginRequest details, String jwt);
}
