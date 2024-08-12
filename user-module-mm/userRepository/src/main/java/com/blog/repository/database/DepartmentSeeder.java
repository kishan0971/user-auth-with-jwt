package com.blog.repository.database;

import com.blog.repository.entity.Department;
import com.blog.repository.repository.DepartmentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

//*The DepartmentSeeder class initializes the department database when the application starts.
//* It checks if specific departments are already in the repository. If not, it creates and saves them.
//* This ensures that predefined departments (like "JAVA", "PYTHON", etc.) are available in the database at startup.
@Component
public class DepartmentSeeder {

    @Autowired
    private DepartmentRepository departmentRepository;

    public void seedDepartments() {
        String[] departmentNames = {
                "JAVA", "PYTHON", "PHP", "ANGULAR", "DATABASE",
                "UI", "HR", "IT", "SALES", "QA", "SUPPORT"
        };

        for (String name : departmentNames) {
            if (departmentRepository.findByName(name).isEmpty()) {
                departmentRepository.save(new Department(name));
                System.out.println("Department '" + name + "' created.");
            } else {
                System.out.println("Department '" + name + "' already exists.");
            }
        }
    }
}