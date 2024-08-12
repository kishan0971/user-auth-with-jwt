package com.blog.repository.database;

import com.blog.repository.entity.Role;
import com.blog.repository.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

//* The RoleSeeder class populates the role database at application startup.
//* It checks if certain roles (like "SUPER_ADMIN", "ADMIN", etc.) exist in the repository.
//* If any roles are missing, it creates and saves them. This ensures that essential roles are preloaded into the database.
@Component
public class RoleSeeder {

    @Autowired
    private RoleRepository roleRepository;

    public void seedRoles() {
        String[] roleNames = {
                "SUPER_ADMIN", "SUPER_AUTHOR", "ADMIN",
                "MANAGER", "EMPLOYEE", "TRAINEE"
        };

        for (String name : roleNames) {
            if (roleRepository.findByName(name).isEmpty()) {
                roleRepository.save(new Role(name));
                System.out.println("Created role '" + name + "'");
            } else {
                System.out.println("Role '" + name + "' already exists.");
            }
        }
    }
}