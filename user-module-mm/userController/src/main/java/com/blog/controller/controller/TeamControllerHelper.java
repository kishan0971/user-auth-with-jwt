package com.blog.controller.controller;



import com.blog.repository.entity.Team;
import com.blog.service.service.teamService.TeamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Component
public class TeamControllerHelper {

    @Autowired
    private TeamService teamService;

    public ResponseEntity<Object> createTeam(String userName, Map<String, String> request) {
        try {
            String name = request.get("name");
            String description = request.get("description");
            if (name == null || name.isEmpty()) {
                return ResponseEntity.badRequest().body(null);
            }

            Team createdTeam = teamService.createTeam(name,description);
            return ResponseEntity.status(HttpStatus.CREATED).body(createdTeam);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    public ResponseEntity<Object> getTeamById(Long id) {
        try {
            Optional<Team> team = teamService.getTeamById(id);
            if (team.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
            }
            return ResponseEntity.ok(team);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    public ResponseEntity<Object> getAllTeams(int page, int size, String sortBy, String sortDir) {
        try {
            Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));
            Page<Team> teams = teamService.getAllTeams(pageable);
            return ResponseEntity.ok(teams);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    public ResponseEntity<Object> searchTeamsByName(String name, int page, int size) {
        try {
            Pageable pageable = PageRequest.of(page, size);
            Page<Team> teams = teamService.searchTeamsByName(name, pageable);
            return ResponseEntity.ok(teams);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    public ResponseEntity<Object> updateTeam(Long id, Map<String, String> request) {
        try {
            String name = request.get("name");
            if (name == null || name.isEmpty()) {
                return ResponseEntity.badRequest().body(null);
            }

            Team updatedTeam = teamService.updateTeam(id, name);
            return ResponseEntity.ok(updatedTeam);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    public ResponseEntity<Object> deleteTeam(Long id) {
        try {
            teamService.deleteTeam(id);
            return ResponseEntity.ok().build();
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public ResponseEntity<Object> restoreTeam(Long id) {
        try {
            Team restoredTeam = teamService.restoreTeam(id);
            return ResponseEntity.ok(restoredTeam);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    public ResponseEntity<List<Team>> getDeletedTeams() {
        try {
            List<Team> deletedTeams = teamService.getDeletedTeams();
            return ResponseEntity.ok(deletedTeams);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }
}
