package com.blog.controller.filter;

import com.blog.controller.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//* The JwtFilter class is a security filter that processes each request to check for a JWT token in the Authorization header.
//* If a valid token is found, it extracts the username, validates the token, and sets the user’s authentication
//* in the security context, enabling secure access to protected resources.
@Component
public class JwtFilter extends OncePerRequestFilter {
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtils jwtUtil;

    //* This method processes incoming HTTP requests to check for a JWT token in the Authorization header.
    //* If the token is present and valid, it extracts the username, loads the user details, validates the token,
    //* and sets the user’s authentication in the security context, enabling secure access to protected resources.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        //* Retrieve the Authorization header from the request
        String authorizationHeader = request.getHeader("Authorization");

        //* Initialize username and JWT variables
        String username = null;
        String jwt = null;

        //* Check if the Authorization header is present and starts with "Bearer "
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            //* Extract the JWT from the Authorization header
            jwt = authorizationHeader.substring(7);
            //* Extract the username from the JWT
            username = jwtUtil.extractUsername(jwt);
        }

        //* If the username is not null, proceed to authenticate the user
        if (username != null) {
            //* Load user details using the extracted username
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            //* Validate the JWT
            if (jwtUtil.validateToken(jwt)) {
                //* Create an authentication token for the user
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                //* Set authentication details from the request
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //* Set the authentication in the security context
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        chain.doFilter(request, response);
    }

}
