package com.blog.service.helper;

import com.blog.repository.entity.User;
import com.blog.service.service.userService.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class ControllerHelper {

@Autowired
private UserServiceImpl userService;

    public Pageable getPageable(int page, int size, String sortColumn, String sort) {
        if (sort != null && !sort.isEmpty()) {
            Sort.Direction sortDirection = Sort.Direction.ASC;
            if (sort.equalsIgnoreCase("desc")) {
                sortDirection = Sort.Direction.DESC;
            }
            if (sortColumn == null || sortColumn.isEmpty()) {
                sortColumn = "id";
            }
            return PageRequest.of(page, size, Sort.by(sortDirection, sortColumn));
        } else {
            return PageRequest.of(page, size);
        }
    }

    public Map<String, Object> buildResponse(List<User> employees, Page<User> result) {
        Map<String, Object> response = new HashMap<>();
        response.put("employees", employees);
        response.put("currentPage", result.getNumber());
        response.put("totalItems", result.getTotalElements());
        response.put("totalPages", result.getTotalPages());
        return response;
    }
    public Map<String, List<String>> fetchInfo(String userName, String departmentName, String teamName, String roleName , int pageNo, int pageSize) {
        Map<String, List<String>> result ;
        if (departmentName != null ) {
            return result = userService.getUsersByDepartment(userName, departmentName, pageNo, pageSize);
        }
        else if (teamName != null) {
            return result = userService.getUsersByTeam(userName, teamName, pageNo, pageSize);
        }
        else if (roleName != null) {
            return  result = userService.getUsersByRolename(userName, roleName, pageNo, pageSize);
        }
        else{
            return  result = userService.getAllUsers(userName, pageNo, pageSize);
        }
    }

}
