package com.blog.service.service.InternalServiceProvider;

import com.blog.repository.entity.User;
import com.blog.repository.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class InternalServiceProviderServiceImpl implements InternalServiceProviderService {

    @Autowired
    private UserRepository userRepository;

    public User findUserByUsername(String userName) {
        return userRepository.findByUserName(userName);
    }
}
