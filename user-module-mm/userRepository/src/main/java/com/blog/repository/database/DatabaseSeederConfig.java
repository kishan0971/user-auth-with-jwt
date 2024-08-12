package com.blog.repository.database;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DatabaseSeederConfig {

    private final RoleSeeder roleSeeder;
    private final DepartmentSeeder departmentSeeder;
    private final TeamSeeder teamSeeder;
    private final UserSeeder userSeeder;

    public DatabaseSeederConfig(RoleSeeder roleSeeder, DepartmentSeeder departmentSeeder,
                                TeamSeeder teamSeeder, UserSeeder userSeeder) {
        this.roleSeeder = roleSeeder;
        this.departmentSeeder = departmentSeeder;
        this.teamSeeder = teamSeeder;
        this.userSeeder = userSeeder;
    }

    @Bean
    public CommandLineRunner databaseSeederRunner() {
        return args -> {
            roleSeeder.seedRoles();        // Run RoleSeeder first
            departmentSeeder.seedDepartments(); // Run DepartmentSeeder next
            //teamSeeder.seedTeams();        // Run TeamSeeder next
            userSeeder.seedSuperAdmin();   // Run UserSeeder last
        };
    }
}