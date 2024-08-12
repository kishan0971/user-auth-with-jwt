package com.blog.repository.database;

import com.blog.repository.entity.Team;
import com.blog.repository.repository.TeamRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

//* The TeamSeeder class initializes the team database upon application startup.
//* It checks for the existence of predefined teams (e.g., "T1", "T2", etc.) in the repository.
//* If any of these teams are missing, they are created and saved, ensuring essential teams are available in the database.
@Component
public class TeamSeeder {

    @Autowired
    private TeamRepository teamRepository;

    public void seedTeams() {
        System.out.println("Started teamSeeder");
        String[] teamNames = {"T1", "T2", "T3", "T4", "T5", "T6"};
        for (String name : teamNames) {
            if (teamRepository.findByName(name).isEmpty()) {
                teamRepository.save(new Team(name));
                System.out.println("Created team: " + name);
            } else {
                System.out.println("Team " + name + " already exists.");
            }
        }
    }
}