package com.blog.controller.controller;

import com.blog.controller.response.ResponseHandler;
import com.blog.controller.utils.JwtUtils;
import com.blog.repository.DTO.LoginRequest;
import com.blog.repository.entity.User;
import com.blog.service.service.InternalServiceProvider.InternalServiceProviderService;
import com.blog.service.service.UserDetailsServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/in2it/blog/public")
public class PublicController {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private InternalServiceProviderService internalServiceProviderServiceImpl;

    @Autowired
    private JwtUtils jwtUtil;

    private static final Logger logger = LoggerFactory.getLogger(PublicController.class);

    @Operation(summary = "Login a user", description = "Handles user login requests. Authenticates the user with provided credentials and returns a JWT token if successful.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful, JWT token returned"),
            @ApiResponse(responseCode = "400", description = "Incorrect username or password")
    })
    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody @Parameter(description = "Login request containing username and password") LoginRequest user) {
        try {
            logger.info("Processing login request for user: {}", user.getUsername());
            User userByUsername = internalServiceProviderServiceImpl.findUserByUsername(user.getUsername());
            if(userByUsername.getDeletedAt() != null) {
                return ResponseHandler.responseBuilder("USER LOGIN UNSUCCESSFUL", HttpStatus.GONE, "USER IS DELETED" );
            }
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
            String jwt = jwtUtil.generateToken(userDetails.getUsername());
            Map<String, Object> response = new HashMap<>();
            response.put("jwt token", jwt);
            response.put("userName", userByUsername.getUserName());
            response.put("email", userByUsername.getEmail());
            response.put("role",userByUsername.getRole().getName());
            return ResponseHandler.responseBuilder("USER LOGIN SUCCESSFUL", HttpStatus.OK, response );
        } catch (Exception e) {
            return ResponseHandler.responseBuilder("USER LOGIN UNSUCCESSFUL", HttpStatus.BAD_REQUEST, "Incorrect username or password" );
        }
    }
}
