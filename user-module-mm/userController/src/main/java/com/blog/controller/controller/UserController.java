package com.blog.controller.controller;

import com.blog.controller.response.ResponseHandler;
import com.blog.repository.auditing.AuditorAwareImpl;
import com.blog.repository.entity.User;
import com.blog.service.helper.ControllerHelper;
import com.blog.service.service.userService.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import com.blog.repository.DTO.UserRequest;
import com.blog.repository.DTO.UserUpdatePassword;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/in2it/blog/user")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private ControllerHelper controllerHelper;

//    @PreAuthorize("hasRole('ADMIN')")
    //* CREATE A NEW AUTHOR

    @Operation(summary = "Create a new author", description = "Allows a super admin or admin to create a new user.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User successfully created"),
            @ApiResponse(responseCode = "400", description = "Invalid input or unauthorized")
    })
    @PostMapping("/create-author")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public ResponseEntity<Object> createNewAuthor(@RequestBody @Parameter(description = "Details of the user to be created") UserRequest userRequest) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            User createdUser = userService.createAuthor(userName, userRequest);
            return ResponseHandler.responseBuilder("User Successfully created", HttpStatus.OK, createdUser);
        } finally {
            AuditorAwareImpl.clear();
        }
    }


    //* UPDATE USER DETAILS

    @Operation(summary = "Update user details", description = "Enables a user to update their own details.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User details updated successfully"),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "400", description = "Invalid input")
    })
    @PutMapping("/self-edit")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN', 'EMPLOYEE', 'SUPER_AUTHOR', 'MANAGER', 'TRAINEE')")
    public ResponseEntity<Object> updateSelfDetails(@RequestBody @Parameter(description = "Updated user details") User user) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            User updatedUser = userService.updateSelfDetails(userName, user);
            return ResponseHandler.responseBuilder("User Successfully updated", HttpStatus.OK, updatedUser);
        }finally {
            AuditorAwareImpl.clear();
        }
    }


    //* CHANGE USER PASSWORD

    @Operation(summary = "Change user password", description = "Allows a user to change their own password.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password updated successfully"),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "400", description = "Invalid input or incorrect current password")
    })
    @PutMapping("/self-edit-password")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN', 'EMPLOYEE', 'SUPER_AUTHOR', 'MANAGER', 'TRAINEE')")
    public ResponseEntity<String> updateSelfPassword(@RequestBody @Parameter(description = "User password update request") UserUpdatePassword userUpdatePassword) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();
        AuditorAwareImpl.setCurrentAuditor(userName);
        userService.updateSelfPassword(userName, userUpdatePassword);
        return ResponseEntity.ok("Successfully updated password");
    }

    //* DELETE A USER

    @Operation(summary = "Soft delete a user", description = "Allows a user to be soft deleted by setting an inactive status.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User soft deleted successfully"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @DeleteMapping("/soft-delete/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Object> softDeleteUser(@PathVariable @Parameter(description = "ID of the user to be soft deleted") Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();
        userService.softDeleteUser(id, userName);
        return ResponseHandler.responseBuilder("Successfully deleted", HttpStatus.OK, "user deleted by"+ userName);
    }

    //* Super Admin fetches all users

    @GetMapping("/super-admin/fetch-all-users")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Object> fetchAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String sortColumn,
            @RequestParam(required = false) String sort,
            @RequestParam(required = false) List<String> searchColumns,
            @RequestParam(required = false) String keyword
    ) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();
        Pageable pageable = controllerHelper.getPageable(page, size, sortColumn, sort);
        Page<User> result = userService.getEveryUser(pageable, searchColumns, keyword);
        List<User> employees = result.getContent();
        if (employees.isEmpty()) {
            return ResponseHandler.responseBuilder("Unsuccessfully fetched", HttpStatus.NO_CONTENT, null );
        }
        Map<String, Object> response = controllerHelper.buildResponse(employees, result);
        return ResponseHandler.responseBuilder("Users Successfully fetched", HttpStatus.OK, response);
    }


    //* Fetch Self Information for profile

    @GetMapping("/self-details")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'EMPLOYEE', 'SUPER_AUTHOR', 'MANAGER', 'TRAINEE')")
    public ResponseEntity<Object> fetchSelfDetails() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();
        Map<String, Object> details = userService.fetchSelfDetails(userName);
        return ResponseHandler.responseBuilder("User Successfully fetched", HttpStatus.OK, details );
    }


    //* Fetch Self Team and Departments for visibility of blogs
    @GetMapping("/self-team-departments")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'EMPLOYEE', 'SUPER_AUTHOR', 'MANAGER', 'TRAINEE')")
    public ResponseEntity<Object> fetchSelfTeamAndDepartments() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();
        Map<String, Object> details = userService.fetchSelfTeamAndDepartments(userName);
        return ResponseHandler.responseBuilder("Teams and Departments Successfully fetched", HttpStatus.OK, details );
    }


    @PatchMapping("/change-role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> changeUserRole(@RequestParam("userId") Long userId, @RequestBody Map<String, String> updates) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();
        userService.changeUserRole(userId, updates.get("roleName"), userName);
        return ResponseHandler.responseBuilder("Update Successfully", HttpStatus.OK, "Successfully changed the role to " + updates.get("roleName"));
    }

}
