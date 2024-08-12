package com.blog.service.service.userService;

import com.blog.repository.DTO.UserRequest;
import com.blog.repository.DTO.UserUpdatePassword;
import com.blog.repository.customQuery.FetchUsersSpecification;
import com.blog.repository.entity.Role;
import com.blog.repository.entity.User;
import com.blog.repository.repository.DepartmentRepository;
import com.blog.repository.repository.RoleRepository;
import com.blog.repository.repository.TeamRepository;
import com.blog.repository.repository.UserRepository;
import com.blog.service.exceptions.*;
import com.blog.service.helper.UserHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {


    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private DepartmentRepository departmentRepository;

    @Autowired
    private TeamRepository teamRepository;

    @Autowired
    private UserHelper userHelper;

    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public User createAuthor(String creatorUsername, UserRequest userRequest) {
        try {
            User user = userRepository.findByUserName(creatorUsername);
            if (user.getRole().getName().matches("SUPER_ADMIN")) {
                return createAdmin(userRequest, creatorUsername);
            } else if (user.getRole().getName().matches("ADMIN")) {
                return createUser(userRequest, creatorUsername);
            } else {
                throw new InvalidRoleAssignmentException("You do not have the valid Role to create a new Author ");
            }
        } catch (Exception e) {
            throw new UnexpectedException("An error occurred while creating the user", e);
        }
    }

    public User createAdmin(UserRequest userRequest, String creator) {
        try {
            //* Validations
            userHelper.validateAdminDTO(userRequest);
            //* Convert DTO to Entity with incoming details
            User userForRepositoryFromDto = userHelper.createUserForRepositoryFromDto(userRequest, creator);
            //* Save and return the User entity
            return userRepository.save(userForRepositoryFromDto);

        } catch (Exception e) {
            //* Handle any other unforeseen exceptions
            throw new UnexpectedException("An error occurred while creating the user", e);
        }
    }

    public User createUser(UserRequest userRequest, String creatorUserName) {
        try {
            //* Validations
            userHelper.validateAuthorDTO(userRequest, creatorUserName);
            //* Convert DTO to Entity with incoming details
            User userForRepositoryFromDto = userHelper.createUserForRepositoryFromDto(userRequest, creatorUserName);
            //* Save and return the User entity
            return userRepository.save(userForRepositoryFromDto);
        } catch (Exception e) {
            //* Handle any other unforeseen exceptions
            throw new UnexpectedException("An error occurred while creating the user", e);
        }
    }


    public User updateSelfDetails(String userName, User user) {
        try {
            //* Find the user by email
            User existingUser = userRepository.findByUserName(userName);
            if (existingUser == null) {
                throw new EmployeeNotFoundException("User not found");
            }
            //* Update user details
            existingUser.setUserName(user.getUserName());
            existingUser.setAddress(user.getAddress());
            existingUser.setMobile(user.getMobile());
            existingUser.setJoiningDate(user.getJoiningDate());
            existingUser.setBackupEmail(user.getBackupEmail());
            //* Save and return the updated user
            return userRepository.save(existingUser);
        } catch (EmployeeNotFoundException e) {
            throw  e;
        } catch (Exception e) {
            //* Handle any other unforeseen exceptions
            throw new UnexpectedException("An unexpected error occurred while updating user details", e);
        }
    }


    public void updateSelfPassword(String userName, UserUpdatePassword userUpdatePassword) {
        try {
            //* Find the user by email
            User existingUser = userRepository.findByUserName(userName);
            if (existingUser == null) {
                throw new EmployeeNotFoundException("User not found");
            }

            //* Check if the old password matches
            if (!passwordEncoder.matches(userUpdatePassword.getOldPassword(), existingUser.getPassword())) {
                throw new PasswordNotMatchException("Old password does not match");
            }

            //* Update the password
            existingUser.setPassword(passwordEncoder.encode(userUpdatePassword.getNewPassword()));

            //* Save the updated user entity
            userRepository.save(existingUser);

        } catch (EmployeeNotFoundException | PasswordNotMatchException e) {
            throw e;
        } catch (Exception e) {
            //* Handle any other unforeseen exceptions
            throw new UnexpectedException("An unexpected error occurred while updating the password", e);
        }
    }

    @Transactional
    public void softDeleteUser(Long userId, String deletedBy) {
        try {
            User user = userRepository.findById(userId).orElse(null);
            if (user != null) {
                String createdBy = user.getCreatedBy();
                if (!createdBy.equals(deletedBy)) {
                    throw new InvalidAccessException("You do not have the valid Access to delete a user");
                }
                userRepository.softDelete(deletedBy, userId);
            } else {
                throw new EmployeeNotFoundException("Author not found");
            }
        } catch (InvalidAccessException | EmployeeNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedException("An unexpected error occurred while deleting the user", e);
        }
    }

    public Page<User> getEveryUser(Pageable pageable, List<String> searchColumns, String keyword) {
        try {
            if (userHelper.hasBothSearchCriteria(searchColumns, keyword)) {
                Specification<User> spec = FetchUsersSpecification.getUsersWithDynamicQuery(searchColumns, keyword);
                return userRepository.findAll(spec, pageable);
            } else if (userHelper.hasKeywordOnly(keyword, searchColumns)) {
                return userRepository.searchAllColumns(keyword, pageable);
            } else {
                return userRepository.findAll(pageable);
            }
        } catch (Exception e) {
            throw new UnexpectedException("An unexpected error occurred while fetching users", e);
        }
    }


    public Map<String, Object> fetchSelfDetails(String userName) {
        try {
            User user = userRepository.findByUserName(userName);
            if (user == null) {
                throw new EmployeeNotFoundException("User not found");
            }
            return userHelper.setUserDetailsForResult(user);
        } catch (EmployeeNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedException("An unexpected error occurred while fetching user details", e);
        }
    }

    public Map<String, Object> fetchSelfTeamAndDepartments(String userName) {
        try {
            User user = userRepository.findByUserName(userName);
            if (user == null) {
                throw new EmployeeNotFoundException("User not found");
            }
            return userHelper.setUserTeamAndDepartment(user);
        } catch (EmployeeNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedException("An unexpected error occurred while fetching user team and departments", e);
        }
    }

    //this method will fetch all the users with their name and department created by loggen in user
    public Map<String, List<String>> getUsersByDepartment(String createdBy, String departmentName, int pageNo, int pageSize) {
        try {
            Pageable paging = PageRequest.of(pageNo, pageSize);
            Page<Object[]> req = userRepository.findByDepartment(createdBy, departmentName, paging);
            //if user doesn't exist it will throw this exception
            if (req == null) {
                throw new EmployeeNotFoundException("User not found");
            }
            //it will return the page content as list
            List<Object[]> results = req.getContent();
            return results.stream()
                    .collect(Collectors.groupingBy(
                            result -> (String) result[0], // UserName
                            Collectors.mapping(result -> (String) result[1], // Department
                                    Collectors.toList())
                    ));
            //* Handle any other unforeseen exceptions
        } catch (Exception ex) {
            throw new UnexpectedException("An unexpected error occurred while fetching user details", ex);
        }
    }

    //this method will fetch all the users with their name and team created by loggen in user
    public Map<String, List<String>> getUsersByTeam(String userName, String teamName, int pageNo, int pageSize) {

        try {
            Pageable paging = PageRequest.of(pageNo, pageSize);
            Page<Object[]> data = userRepository.findByTeam(userName, teamName, paging);
            //if user doesn't exist it will throw this exception
            if (data == null) {
                throw new EmployeeNotFoundException("User not found");
            }
            //it will return the page content as list
            List<Object[]> results = (List<Object[]>) data.getContent();
            return results.stream()
                    .collect(Collectors.groupingBy(
                            result -> (String) result[0], // UserName
                            Collectors.mapping(result -> (String) result[1], // Team
                                    Collectors.toList())
                    ));
            //* Handle any other  exceptions
        } catch (Exception ex) {
            throw new UnexpectedException("An unexpected error occurred while fetching user details", ex);
        }
    }

    //this method will fetch username and rolename of the users created by admin
    public Map<String, List<String>> getUsersByRolename(String userName, String roleName, int pageNo, int pageSize) {

        try {
            Pageable paging = PageRequest.of(pageNo, pageSize);
            Page<Object[]> data = userRepository.findByRole(userName, roleName, paging);
            //if user doesn't exist it will throw this exception
            if (data == null) {
                throw new EmployeeNotFoundException("No User exists");
            }
            //it will return the page content as list
            List<Object[]> results = (List<Object[]>) data.getContent();
            return results.stream()
                    .collect(Collectors.groupingBy(
                            result -> (String) result[0], // UserName
                            Collectors.mapping(result -> (String) result[1], // Rolename
                                    Collectors.toList())
                    ));
        } catch (Exception ex) {
            throw new UnexpectedException("An unexpected error occurred while fetching user details", ex);
        }
    }

    //this method will fetch all the users with their role , department and teams created by admin
    public Map<String, List<String>> getAllUsers(String userName, int pageNo, int pageSize) {
        Pageable paging = PageRequest.of(pageNo, pageSize);
        User user = userRepository.findByUserName(userName);
        //if user doesn't exist it will throw this exception
        if (user == null) {
            throw new EmployeeNotFoundException("User not found");
        }
        //fetch all the users with their role , departement and team
        return userHelper.getUsersDetailsCreatedBy(userName);

    }


    public void changeUserRole(Long userId, String newRole, String userName) {
        try {
            User user = userRepository.findById(userId).orElseThrow(() -> new EmployeeNotFoundException("User not found"));
            if (!user.getCreatedBy().equals(userName)) {
                throw new InvalidAccessException("You cannot change the role of this user");
            }
            Optional<Role> roleOpt = roleRepository.findByName(newRole);
            if (roleOpt.isEmpty()) {
                throw new InvalidAccessException("Role " + newRole + " does not exist");
            }
            Role role = roleOpt.get();
            String roleName = role.getName();
            if (roleName.equals("SUPER_ADMIN") || roleName.equals("SUPER_AUTHOR") || roleName.equals("ADMIN")) {
                throw new InvalidAccessException("You cannot assign the " + roleName + " role to a user");
            }
            user.setRole(role);
            userRepository.save(user);
        } catch (EmployeeNotFoundException | InvalidAccessException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedException("An unexpected error occurred while changing the user's role", e);
        }
    }

}