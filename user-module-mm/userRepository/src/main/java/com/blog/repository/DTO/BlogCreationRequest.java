package com.blog.repository.DTO;

import com.blog.repository.entity.Department;
import com.blog.repository.entity.Role;
import com.blog.repository.entity.Team;
import org.springframework.web.multipart.MultipartFile;

import java.lang.reflect.Array;
import java.util.List;

public class BlogCreationRequest {

    private String title;
    private String content;
    private Long[] team_visibility;
    private Long[] department_visibility;
    private MultipartFile[] files; // Base64 encoded files

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public Long[] getTeam_visibility() {
        return team_visibility;
    }

    public void setTeam_visibility(Long[] team_visibility) {
        this.team_visibility = team_visibility;
    }

    public Long[] getDepartment_visibility() {
        return department_visibility;
    }

    public void setDepartment_visibility(Long[] department_visibility) {
        this.department_visibility = department_visibility;
    }

    public MultipartFile[] getFiles() {
        return files;
    }

    public void setFiles(MultipartFile[] files) {
        this.files = files;
    }
}
