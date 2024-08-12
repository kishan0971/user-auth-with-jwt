package com.blog.service.exceptions;

public class InvalidAccessException extends  RuntimeException {
    public InvalidAccessException(String message) {
        super(message);
    }
    public InvalidAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}
