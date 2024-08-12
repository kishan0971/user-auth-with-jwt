package com.blog.service.service.teamService;

import com.blog.repository.entity.Team;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

public interface TeamService {

    Team createTeam(String teamName,String description);

    Optional<Team> getTeamById(Long id);

    Team getTeamByName(String name);

    Page<Team> getAllTeams(Pageable pageable);

    Page<Team> searchTeamsByName(String name, Pageable pageable);

    Team updateTeam(Long id, String teamName);

    void deleteTeam(Long id);

    Team restoreTeam(Long id);

    List<Team> getDeletedTeams();
}
