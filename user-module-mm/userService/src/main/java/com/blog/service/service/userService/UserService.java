package com.blog.service.service.userService;

import com.blog.repository.DTO.UserRequest;
import com.blog.repository.DTO.UserUpdatePassword;
import com.blog.repository.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Map;

public interface UserService {

    User createAuthor(String creatorUsername, UserRequest userRequest);

    User createAdmin(UserRequest userRequest, String creator);

    User createUser(UserRequest userRequest, String creatorUserName);

    User updateSelfDetails(String userName, User user);

    void updateSelfPassword(String userName, UserUpdatePassword userUpdatePassword);

    void softDeleteUser(Long userId, String deletedBy);

    Page<User> getEveryUser(Pageable pageable, List<String> searchColumns, String keyword);

    Map<String, Object> fetchSelfDetails(String userName);

    Map<String, Object> fetchSelfTeamAndDepartments(String userName);

    Map<String, List<String>> getUsersByDepartment(String createdBy, String departmentName, int pageNo, int pageSize);

    Map<String, List<String>> getUsersByTeam(String userName, String teamName, int pageNo, int pageSize);

    Map<String, List<String>> getUsersByRolename(String userName, String roleName, int pageNo, int pageSize);

    Map<String, List<String>> getAllUsers(String userName, int pageNo, int pageSize);

    void changeUserRole(Long userId, String newRole, String userName);
}
