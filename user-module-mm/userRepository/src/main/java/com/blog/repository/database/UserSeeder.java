package com.blog.repository.database;

import com.blog.repository.entity.Role;
import com.blog.repository.entity.User;
import com.blog.repository.repository.RoleRepository;
import com.blog.repository.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.GregorianCalendar;

@Component
public class UserSeeder {

    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    public void seedSuperAdmin() {
        System.out.println("Stared UserSeeder");
        User user = userRepository.findByUserName("Super Admin");
        if (user == null) {
            System.out.println("Started to seed user_master");
            Role superAdminRole = roleRepository.findByName("SUPER_ADMIN")
                    .orElseThrow(() -> new IllegalArgumentException("Role not found"));
            User superAdmin = new User();
            superAdmin.setUserName("Super Admin");
            superAdmin.setEmail("super_admin@in2it.com");
            superAdmin.setPassword(passwordEncoder.encode("h3G8kL2nW9pQ"));
            superAdmin.setName("Super Admin");
            superAdmin.setStatus("ACTIVE");
            superAdmin.setPostCreate(true);
            superAdmin.setAddress("NOIDA");
            superAdmin.setMobile("9999999999");
            superAdmin.setJoiningDate(new GregorianCalendar(2024, Calendar.JANUARY, 1).getTime());
            superAdmin.setBackupEmail("super_admin@in2it.com");
            superAdmin.setEmpCode("00000000");
            superAdmin.setDepartments(null); // or simply don't set this field
            superAdmin.setTeams(null); // or simply don't set this field
            superAdmin.setRole(superAdminRole);
            userRepository.save(superAdmin);
            System.out.println("Super Admin created.");
        } else {
            System.out.println("Super Admin already exists.");
        }
    }
}