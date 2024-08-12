package com.blog.controller;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication(scanBasePackages = {"com.blog"})
@EnableJpaAuditing
@EnableTransactionManagement
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@EnableFeignClients(basePackages = "com.blog.service.externalServices")
public class UserModuleApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserModuleApplication.class, args);
    }
}










