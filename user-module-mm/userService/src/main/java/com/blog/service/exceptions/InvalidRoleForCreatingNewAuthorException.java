package com.blog.service.exceptions;

public class InvalidRoleForCreatingNewAuthorException extends RuntimeException{
    public InvalidRoleForCreatingNewAuthorException(String message) {
        super(message);
    }
    public InvalidRoleForCreatingNewAuthorException(String message, Throwable cause) {
        super(message, cause);
    }
}
