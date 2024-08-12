package com.blog.service.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class RestExceptionHandler {

    @ExceptionHandler(value = {EmployeeNotFoundException.class})
    public ResponseEntity<Object> handleEmployeeNotFoundException(EmployeeNotFoundException ex) {
        return buildResponseEntityForExceptions(ex, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(value = {InvalidRoleAssignmentException.class})
    public ResponseEntity<Object> handleInvalidRoleAssignmentException(InvalidRoleAssignmentException ex) {
        return buildResponseEntityForExceptions(ex, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(value = {InvalidRoleForCreatingNewAuthorException.class})
    public ResponseEntity<Object> handleInvalidRoleForCreatingNewAuthorException(InvalidRoleForCreatingNewAuthorException ex) {
        return buildResponseEntityForExceptions(ex, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(value = {InvalidAccessException.class})
    public ResponseEntity<Object> handleInvalidAccessException(InvalidAccessException ex) {
        return buildResponseEntityForExceptions(ex, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(value = {UnexpectedException.class})
    public ResponseEntity<Object> handleUnexpectedException(UnexpectedException ex) {
        return buildResponseEntityForExceptions(ex, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(value = {TeamNotFoundException.class})
    public ResponseEntity<Object> handleTeamNotFoundException(TeamNotFoundException ex) {
        return buildResponseEntityForExceptions(ex, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(value = {DepartmentNotFoundException.class})
    public ResponseEntity<Object> handleDepartmentNotFoundException(DepartmentNotFoundException ex) {
        return buildResponseEntityForExceptions(ex, HttpStatus.NOT_FOUND);
    }

    private ResponseEntity<Object> buildResponseEntityForExceptions(RuntimeException ex, HttpStatus status) {
        RestException restException = new RestException(
                ex.getMessage(),
                ex.getCause(),
                status
        );
        return new ResponseEntity<>(restException, status);
    }

}