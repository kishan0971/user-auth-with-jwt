package com.blog.service.exceptions;

import com.blog.repository.entity.Team;

public class TeamNotFoundException extends RuntimeException {
    public TeamNotFoundException(String s) {
        super(s);
    }

    public TeamNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
