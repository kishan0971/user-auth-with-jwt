package com.blog.service.service.teamService;

import com.blog.repository.entity.Team;
import com.blog.repository.repository.TeamRepository;
import com.blog.service.exceptions.InvalidAccessException;
import com.blog.service.exceptions.TeamNotFoundException;
import com.blog.service.exceptions.UnexpectedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class TeamServiceImpl implements TeamService {

    @Autowired
    private TeamRepository teamRepository;

    private static final Pattern TEAM_NAME_PATTERN = Pattern.compile("^[A-Za-z0-9 _-]{3,50}$"); // Example regex pattern
    private static final Pattern ID_PATTERN = Pattern.compile("^[1-9][0-9]*$"); // Regex for positive integers

    // Create a new team
    public Team createTeam(String teamName,String description) {
        try {
            validateTeamName(teamName); // Validate the team name
            Team team = new Team(teamName,description);
            return teamRepository.save(team);
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while creating the team", e);
        }
    }

    // Retrieve a team by its ID
    public Optional<Team> getTeamById(Long id) {
        try {
            validateId(id); // Validate the ID
            return teamRepository.findByIdActive(id);
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while retrieving the team by ID", e);
        }
    }

    // Retrieve a team by its name
    public Team getTeamByName(String name) {
        try {
            validateTeamName(name); // Validate the team name
            return teamRepository.findByNameContainingIgnoreCaseActive(name, Pageable.unpaged())
                    .stream()
                    .findFirst()
                    .orElseThrow(() -> new TeamNotFoundException("Team not found"));
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while retrieving the team by name", e);
        }
    }

    // Retrieve all active teams with pagination
    public Page<Team> getAllTeams(Pageable pageable) {
        try {
            return teamRepository.findAllActive(pageable);
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while retrieving all teams", e);
        }
    }

    // Search teams by name with pagination
    public Page<Team> searchTeamsByName(String name, Pageable pageable) {
        try {
            validateTeamName(name); // Validate the team name
            return teamRepository.findByNameContainingIgnoreCaseActive(name, pageable);
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while searching teams by name", e);
        }
    }

    // Update a team
    public Team updateTeam(Long id, String teamName) {
        try {
            validateId(id); // Validate the ID
            validateTeamName(teamName); // Validate the team name

            Team team = teamRepository.findByIdActive(id)
                    .orElseThrow(() -> new TeamNotFoundException("Team not found or not authorized to update"));
            if (!isAuthorizedToUpdate(team)) {
                throw new InvalidAccessException("Not authorized to update this team");
            }
            team.setName(teamName);
            return teamRepository.save(team);
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while updating the team", e);
        }
    }

    // Soft delete a team
    @Transactional
    public void deleteTeam(Long id) {
        try {
            validateId(id); // Validate the ID
            String currentUser = getCurrentUsername();
            teamRepository.softDelete(id, currentUser, LocalDateTime.now());
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while deleting the team", e);
        }
    }

    // Restore a soft-deleted team
    @Transactional
    public Team restoreTeam(Long id) {
        try {
            validateId(id); // Validate the ID
            Team team = teamRepository.findByIdActive(id)
                    .orElseThrow(() -> new TeamNotFoundException("Team not found or not authorized to restore"));
            if (!isAuthorizedToRestore(team)) {
                throw new InvalidAccessException("Not authorized to restore this team");
            }
            teamRepository.restore(id);
            return teamRepository.findByIdActive(id)
                    .orElseThrow(() -> new TeamNotFoundException("Failed to restore team"));
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while restoring the team", e);
        }
    }

    // Get deleted teams for restoration
    public List<Team> getDeletedTeams() {
        try {
            return teamRepository.findAllDeleted();
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while retrieving deleted teams", e);
        }
    }

    // Utility method to get the current username from the security context
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof String) {
            return (String) authentication.getPrincipal();
        }
        throw new UnexpectedException("Unable to retrieve current user");
    }

    // Utility method to check if the current user is authorized to update the team
    private boolean isAuthorizedToUpdate(Team team) {
        String currentUsername = getCurrentUsername();
        return currentUsername.equals(team.getCreatedBy());
    }

    // Utility method to check if the current user is authorized to restore the team
    private boolean isAuthorizedToRestore(Team team) {
        String currentUsername = getCurrentUsername();
        return currentUsername.equals(team.getDeletedBy());
    }

    // Utility method to validate team name using regex
    private void validateTeamName(String teamName) {
        if (teamName == null || !TEAM_NAME_PATTERN.matcher(teamName).matches()) {
            throw new IllegalArgumentException("Team name must be between 3 and 50 characters and can only contain letters, numbers, spaces, underscores, and hyphens");
        }
    }

    // Utility method to validate ID using regex
    private void validateId(Long id) {
        if (id == null || !ID_PATTERN.matcher(id.toString()).matches()) {
            throw new IllegalArgumentException("Invalid ID");
        }
    }
}
