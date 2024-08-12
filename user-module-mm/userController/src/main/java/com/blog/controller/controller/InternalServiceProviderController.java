package com.blog.controller.controller;

import com.blog.controller.response.ResponseHandler;
import com.blog.repository.entity.User;
import com.blog.service.service.InternalServiceProvider.InternalServiceProviderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/in2it/internal/controller")
public class InternalServiceProviderController {

    @Autowired
    private InternalServiceProviderService service;

    @PostMapping("/validate-jwt-token")
    public ResponseEntity<Object> validateJwtToken(@RequestHeader("Authorization") String authorizationHeader){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();
        if(userName != null){
            User user = service.findUserByUsername(userName);
            if (user != null) {
                Map<String, Object> response = new HashMap<>();
                response.put("valid", true);
                response.put("userId", user.getId());
                response.put("userName", user.getUserName());
                return ResponseHandler.responseBuilder("Token validated successfully", HttpStatus.OK, response);
            } else {
                return ResponseHandler.responseBuilder("User not found", HttpStatus.UNAUTHORIZED, "Token is invalid");
            }
        } else {
            return ResponseHandler.responseBuilder("Token validated successfully", HttpStatus.UNAUTHORIZED, "Token is invalid");
        }
    }

}
