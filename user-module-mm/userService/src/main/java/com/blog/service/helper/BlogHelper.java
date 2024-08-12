package com.blog.service.helper;

import com.blog.repository.repository.DepartmentRepository;
import com.blog.repository.repository.TeamRepository;
import com.blog.service.exceptions.DepartmentNotFoundException;
import com.blog.service.exceptions.TeamNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class BlogHelper {

    @Autowired
    private TeamRepository teamRepository;

    @Autowired
    private DepartmentRepository departmentRepository;

    public void checkExistenceOfTeam(Long[] teamVisibility){
        for(Long team : teamVisibility){
            teamRepository.findById(team).orElseThrow(() -> new TeamNotFoundException("Invalid Team"));
        }
    }

    public void checkExistenceOfDepartment(Long[] departmentVisibility){
        for(Long department : departmentVisibility){
            departmentRepository.findById(department).orElseThrow(() -> new DepartmentNotFoundException("Invalid Department"));
        }
    }


}
