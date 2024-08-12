package com.blog.service.service.publicService;

import com.blog.repository.DTO.LoginRequest;
import com.blog.repository.entity.User;
import com.blog.repository.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class PublicServiceImpl implements PublicService {

    @Autowired
    private UserRepository userRepository;

    public void loginService(LoginRequest details, String jwt){
        User user = userRepository.findByUserName(details.getUsername());
        Map<String, Object> response = new HashMap<>();
        response.put("jwtToken", jwt);
        response.put("userName",user.getUserName());
        response.put("email",user.getEmail());
        response.put("name",user.getName());
        response.put("role",user.getRole().getName());
        response.put("userId",user.getId());
        response.put("departments",user.getDepartments().toArray());
        response.put("",user.getUserName());
        response.put("",user.getUserName());
        response.put("",user.getUserName());



    }


}
