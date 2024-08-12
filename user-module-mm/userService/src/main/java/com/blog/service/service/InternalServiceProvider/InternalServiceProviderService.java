package com.blog.service.service.InternalServiceProvider;

import com.blog.repository.entity.User;

public interface InternalServiceProviderService {

    User findUserByUsername(String username);
}
