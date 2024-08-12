package com.blog.service.helper;

import com.blog.repository.DTO.UserRequest;
import com.blog.repository.entity.Department;
import com.blog.repository.entity.Role;
import com.blog.repository.entity.Team;
import com.blog.repository.entity.User;
import com.blog.repository.repository.DepartmentRepository;
import com.blog.repository.repository.RoleRepository;
import com.blog.repository.repository.TeamRepository;
import com.blog.repository.repository.UserRepository;
import com.blog.service.exceptions.EmployeeNotFoundException;
import com.blog.service.exceptions.InvalidRoleAssignmentException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class UserHelper {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private DepartmentRepository departmentRepository;

    @Autowired
    private TeamRepository teamRepository;

    @Autowired
    private UserRepository userRepository;

    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public Role assignRoleToUser(UserRequest userRequest) {
        return roleRepository.findByName(userRequest.getRole())
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));
    }

    public Set<Department> assignDepartmentsToUser(UserRequest userRequest){
        return userRequest.getDepartment().stream()
                .map(deptName -> departmentRepository.findByName(deptName)
                        .orElseThrow(() -> new IllegalArgumentException("Department not found: " + deptName)))
                .collect(Collectors.toSet());
    }

    public Set<Team> assignTeamsToUser(UserRequest userRequest) {
        return userRequest.getTeam().stream()
                .map(teamName -> teamRepository.findByName(teamName)
                        .orElseThrow(() -> new IllegalArgumentException("Team not found: " + teamName)))
                .collect(Collectors.toSet());
    }

    public void validateAdminDTO(UserRequest userRequest) {
        // Validate role
        List<String> validRoles = Arrays.asList("SUPER_ADMIN", "MANAGER", "EMPLOYEE", "TRAINEE");
        if (validRoles.contains(userRequest.getRole())) {
            throw new InvalidRoleAssignmentException("You do not have the necessary permissions to create a user with "+ userRequest.getRole() +" role.");
        }

        // Validate email
        if (userRequest.getEmail() == null || userRequest.getEmail().isEmpty() || !userRequest.getEmail().matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
            throw new IllegalArgumentException("Email must be non-empty and in a valid format.");
        }

        // Validate name
        if (userRequest.getName() == null || userRequest.getName().isEmpty() || !userRequest.getName().matches("^[a-zA-Z0-9 ]*$")) {
            throw new IllegalArgumentException("Name must be non-empty and contain only alphanumeric characters and spaces.");
        }

        // Validate employee code
        if (userRequest.getEmpCode() == null || userRequest.getEmpCode().isEmpty() || !userRequest.getEmpCode().matches("^[a-zA-Z0-9 ]*$")) {
            throw new IllegalArgumentException("Employee Code must be non-empty and contain only alphanumeric characters and spaces.");
        }

        // Validate address
        if (userRequest.getAddress() == null || userRequest.getAddress().isEmpty()) {
            throw new IllegalArgumentException("Address must be non-empty.");
        }

        // Validate mobile number
        if (userRequest.getMobile() == null || userRequest.getMobile().isEmpty() || !userRequest.getMobile().matches("^\\d{10}$")) {
            throw new IllegalArgumentException("Mobile number must be a 10-digit number.");
        }

        // Validate backup email
        if (userRequest.getBackupEmail() != null && !userRequest.getBackupEmail().isEmpty() && !userRequest.getBackupEmail().matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
            throw new IllegalArgumentException("Backup Email must be in a valid format.");
        }

        // Validate joining date
        if (userRequest.getJoinDate() == null) {
            throw new IllegalArgumentException("Joining Date must not be null.");
        }
    }

    public void validateAuthorDTO(UserRequest userRequest, String creatorUserName) {
        if ("SUPER_ADMIN".equals(userRequest.getRole()) ||
                "ADMIN".equals(userRequest.getRole()) ||
                "SUPER_AUTHOR".equals(userRequest.getRole())) {
            throw new InvalidRoleAssignmentException("You do not have the necessary permissions to create a user with "+ userRequest.getRole() +" role.");
        }
        if (userRequest.getEmail() == null || userRequest.getEmail().isEmpty() || !userRequest.getEmail().matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
            throw new IllegalArgumentException("Email must be non-empty and in a valid format");
        }
        if (userRequest.getName() == null || userRequest.getName().isEmpty() || !userRequest.getName().matches("^[a-zA-Z0-9 ]*$")) {
            throw new IllegalArgumentException("Name must be non-empty and contain only alphanumeric characters");
        }
        if (userRequest.getEmpCode() == null || userRequest.getEmpCode().isEmpty() || !userRequest.getEmpCode().matches("^[a-zA-Z0-9 ]*$")) {
            throw new IllegalArgumentException("Employee Code must be non-empty and contain only alphanumeric characters");
        }
        System.out.println(userRepository.findByUserName(creatorUserName));
    }

    public User createUserForRepositoryFromDto(UserRequest userRequest,String creatorUserName) {
        // Create and populate User entity
        User creator = userRepository.findByUserName(creatorUserName);
        User user = new User();
        user.setEmail(userRequest.getEmail());
        user.setName(userRequest.getName());
        user.setEmpCode(userRequest.getEmpCode());
        user.setManagerId(creator.getId());
        user.setAddress(userRequest.getAddress());
        user.setMobile(userRequest.getMobile());
        user.setBackupEmail(userRequest.getBackupEmail());
        user.setJoiningDate(userRequest.getJoinDate());
        user.setPassword(passwordEncoder.encode("in2it" )); //* Encoding password
        user.setUserName(userRequest.getEmpCode()); //* Assuming userName is same as emp code which can be later changed
        if (userRequest.getTeam() != null) {
            user.setTeams(assignTeamsToUser(userRequest));
        }
        // Assign role, departments, and teams is null
        user.setRole(assignRoleToUser(userRequest));
        user.setDepartments(assignDepartmentsToUser(userRequest));

        return user;
    }

    public boolean hasBothSearchCriteria(List<String> searchColumns, String keyword) {
        return searchColumns != null && !searchColumns.isEmpty() && keyword != null && !keyword.isEmpty();
    }

    public boolean hasKeywordOnly(String keyword, List<String> searchColumns) {
        return keyword != null && !keyword.isEmpty() && (searchColumns == null || searchColumns.isEmpty());
    }

    public Map<String, Object> setUserDetailsForResult(User user) {
        Map<String, Object> userDetails = new HashMap<>();
        userDetails.put("id", user.getId());
        userDetails.put("userName", user.getUserName());
        userDetails.put("email", user.getEmail());
        userDetails.put("name", user.getName());
        userDetails.put("empCode", user.getEmpCode());
        userDetails.put("address", user.getAddress());
        userDetails.put("mobile", user.getMobile());
        userDetails.put("backupEmail", user.getBackupEmail());
        userDetails.put("joiningDate", user.getJoiningDate());
        userDetails.put("role", user.getRole().getName());
        userDetails.put("departments", user.getDepartments().stream().map(Department::getName).collect(Collectors.toList()));
        userDetails.put("teams", user.getTeams().stream().map(Team::getName).collect(Collectors.toList()));
        if (user.getManagerId() != null) {
            User manager = userRepository.findById(user.getManagerId()).orElseThrow(() -> new EmployeeNotFoundException("Couldn't find a manager"));
            userDetails.put("manager", manager.getName());
        } else {
            userDetails.put("manager", "No Manager");
        }
        userDetails.put("canCreateBlogs", user.isPostCreate());
        return userDetails;
    }

    public Map<String, Object> setUserTeamAndDepartment(User user) {
        Map<String, Object> userDetails = new HashMap<>();
        userDetails.put("departments", user.getDepartments().stream().map(Department::getName).collect(Collectors.toList()));
        userDetails.put("teams", user.getTeams().stream().map(Team::getName).collect(Collectors.toList()));
        return userDetails;
    }


    public Map<String, List<String>> getUsersDetailsCreatedBy(String createdBy) {
        List<User> users = userRepository.findUserCreatedBy(createdBy);
        return users.stream().collect(Collectors.toMap(
                User::getUserName,
                user -> {
                    List<String> details = new ArrayList<>();
                    details.add("Role: " + user.getRole().getName());
                    details.addAll(user.getDepartments().stream()
                            .map(department -> "Department: " + department.getName())
                            .collect(Collectors.toList()));
                    details.addAll(user.getTeams().stream()
                            .map(team -> "Team: " + team.getName())
                            .collect(Collectors.toList()));
                    return details;
                }
        ));
    }

}
