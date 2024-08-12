package com.blog.controller.controller;


import com.blog.controller.response.ResponseHandler;
import com.blog.repository.auditing.AuditorAwareImpl;

import com.blog.service.helper.ControllerHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("in2it/blog/user")
public class FetchDetailsController {

    @Autowired
    private ControllerHelper controllerHelper;



    @GetMapping("/fetchusers")
    private ResponseEntity<Object> getUsers(
            @RequestParam(name = "departmentName", required = false) String departmentName,
            @RequestParam(name = "teamName", required = false) String teamName,
            @RequestParam(name = "roleName", required = false) String roleName,
            @RequestParam(defaultValue = "0", name = "pageNo") int pageNo,
            @RequestParam(defaultValue = "10", name = "pageSize") int pageSize
    ) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userName = authentication.getName();
            AuditorAwareImpl.setCurrentAuditor(userName);
            Map<String, List<String>> result = controllerHelper.fetchInfo(userName, departmentName, teamName, roleName, pageNo, pageSize);
            return ResponseHandler.responseBuilder("Users fetched successfully", HttpStatus.OK, result);

        } finally {
            AuditorAwareImpl.clear();
        }

    }



}
