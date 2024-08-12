package com.blog.service.exceptions;

public class InvalidRoleAssignmentException extends RuntimeException {
    public InvalidRoleAssignmentException(String message) {
        super(message);
    }
    public InvalidRoleAssignmentException(String message, Throwable cause) {
        super(message, cause);
    }
}
