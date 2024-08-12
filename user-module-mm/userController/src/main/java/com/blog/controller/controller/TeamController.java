package com.blog.controller.controller;


import com.blog.controller.response.ResponseHandler;
import com.blog.repository.auditing.AuditorAwareImpl;
import com.blog.repository.entity.Team;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/in2it/blog/team")
public class TeamController {

    @Autowired
    private TeamControllerHelper teamControllerHelper;

    @Operation(summary = "Creates a new team with the provided name and description.", description = "Creates a new team with the provided name & description.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Team created successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input"),
            @ApiResponse(responseCode = "403", description = "Forbidden, insufficient role or invalid JWT token")
    })
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> createTeam(@RequestBody @Parameter(description = "Details of the team to be created") Map<String, String> request) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            return teamControllerHelper.createTeam(userName, request);
        } catch (AccessDeniedException e) {
            return ResponseHandler.responseBuilder("Forbidden, insufficient role", HttpStatus.FORBIDDEN, null);
        } catch (Exception e) {
            return ResponseHandler.responseBuilder("Error occurred while creating team", HttpStatus.INTERNAL_SERVER_ERROR, null);
        } finally {
            AuditorAwareImpl.clear();
        }
    }

    @Operation(summary = "Get a team by ID", description = "Retrieves a team by its ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Team found"),
            @ApiResponse(responseCode = "404", description = "Team not found"),
            @ApiResponse(responseCode = "403", description = "Forbidden, insufficient role or invalid JWT token")
    })
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> getTeamById(@PathVariable @Parameter(description = "ID of the team to retrieve") Long id) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            return teamControllerHelper.getTeamById(id);
        } catch (AccessDeniedException e) {
            return ResponseHandler.responseBuilder("Forbidden, insufficient role", HttpStatus.FORBIDDEN, null);
        } catch (Exception e) {
            return ResponseHandler.responseBuilder("Error occurred while retrieving team", HttpStatus.INTERNAL_SERVER_ERROR, null);
        } finally {
            AuditorAwareImpl.clear();
        }
    }

    @Operation(summary = "Get all active teams", description = "Retrieves all active teams with pagination.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of active teams retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Forbidden, insufficient role or invalid JWT token")
    })
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> getAllTeams(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "name") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir
    ) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            return teamControllerHelper.getAllTeams(page, size, sortBy, sortDir);
        } catch (AccessDeniedException e) {
            return ResponseHandler.responseBuilder("Forbidden, insufficient role", HttpStatus.FORBIDDEN, null);
        } catch (Exception e) {
            return ResponseHandler.responseBuilder("Error occurred while retrieving teams", HttpStatus.INTERNAL_SERVER_ERROR, null);
        } finally {
            AuditorAwareImpl.clear();
        }
    }

    @Operation(summary = "Search teams by name", description = "Searches for teams by their name with pagination.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of teams matching the search criteria retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Forbidden, insufficient role or invalid JWT token")
    })
    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> searchTeamsByName(
            @RequestParam String name,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            return teamControllerHelper.searchTeamsByName(name, page, size);
        } catch (AccessDeniedException e) {
            return ResponseHandler.responseBuilder("Forbidden, insufficient role", HttpStatus.FORBIDDEN, null);
        } catch (Exception e) {
            return ResponseHandler.responseBuilder("Error occurred while searching teams", HttpStatus.INTERNAL_SERVER_ERROR, null);
        } finally {
            AuditorAwareImpl.clear();
        }
    }

    @Operation(summary = "Update a team", description = "Updates the details of an existing team.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Team updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input"),
            @ApiResponse(responseCode = "404", description = "Team not found"),
            @ApiResponse(responseCode = "403", description = "Forbidden, insufficient role or invalid JWT token")
    })
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> updateTeam(
            @PathVariable @Parameter(description = "ID of the team to be updated") Long id,
            @RequestBody @Parameter(description = "Updated team details") Map<String, String> request
    ) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            return teamControllerHelper.updateTeam(id, request);
        } catch (AccessDeniedException e) {
            return ResponseHandler.responseBuilder("Forbidden, insufficient role", HttpStatus.FORBIDDEN, null);
        } catch (Exception e) {
            return ResponseHandler.responseBuilder("Error occurred while updating team", HttpStatus.INTERNAL_SERVER_ERROR, null);
        } finally {
            AuditorAwareImpl.clear();
        }
    }

    @Operation(summary = "Delete a team", description = "Soft deletes a team by its ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Team soft deleted successfully"),
            @ApiResponse(responseCode = "404", description = "Team not found"),
            @ApiResponse(responseCode = "403", description = "Forbidden, insufficient role or invalid JWT token")
    })
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> deleteTeam(@PathVariable @Parameter(description = "ID of the team to be deleted") Long id) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            return teamControllerHelper.deleteTeam(id);
        } catch (AccessDeniedException e) {
            return ResponseHandler.responseBuilder("Forbidden, insufficient role", HttpStatus.FORBIDDEN, null);
        } catch (Exception e) {
            return ResponseHandler.responseBuilder("Error occurred while deleting team", HttpStatus.INTERNAL_SERVER_ERROR, null);
        } finally {
            AuditorAwareImpl.clear();
        }
    }

    @Operation(summary = "Restore a soft-deleted team", description = "Restores a previously soft-deleted team by its ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Team restored successfully"),
            @ApiResponse(responseCode = "404", description = "Team not found"),
            @ApiResponse(responseCode = "403", description = "Forbidden, insufficient role or invalid JWT token")
    })
    @PostMapping("/restore/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> restoreTeam(@PathVariable @Parameter(description = "ID of the team to be restored") Long id) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            return teamControllerHelper.restoreTeam(id);
        } catch (AccessDeniedException e) {
            return ResponseHandler.responseBuilder("Forbidden, insufficient role", HttpStatus.FORBIDDEN, null);
        } catch (Exception e) {
            return ResponseHandler.responseBuilder("Error occurred while restoring team", HttpStatus.INTERNAL_SERVER_ERROR, null);
        } finally {
            AuditorAwareImpl.clear();
        }
    }

    @Operation(summary = "Get deleted teams for restoration", description = "Retrieves teams that have been soft-deleted.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of deleted teams retrieved successfully"),
            @ApiResponse(responseCode = "404", description = "No deleted teams found"),
            @ApiResponse(responseCode = "403", description = "Forbidden, insufficient role or invalid JWT token"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @GetMapping("/deleted")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> getDeletedTeams() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);

            List<Team> teams = (List<Team>) teamControllerHelper.getDeletedTeams();
            if (teams.isEmpty()) {
                return ResponseHandler.responseBuilder("No deleted teams found", HttpStatus.NOT_FOUND, null);
            }
            return ResponseHandler.responseBuilder("Deleted teams retrieved successfully", HttpStatus.OK, teams);
        } catch (AccessDeniedException e) {
            return ResponseHandler.responseBuilder("Forbidden, insufficient role", HttpStatus.FORBIDDEN, null);
        } catch (AuthenticationException e) {
            return ResponseHandler.responseBuilder("Invalid authentication token", HttpStatus.UNAUTHORIZED, null);
        } catch (Exception e) {
            // Log the exception details
            // logger.error("Error occurred while retrieving deleted teams", e);
            return ResponseHandler.responseBuilder("Error occurred while retrieving deleted teams", HttpStatus.INTERNAL_SERVER_ERROR, null);
        } finally {
            AuditorAwareImpl.clear();
        }
    }
}
