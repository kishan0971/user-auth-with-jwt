package com.blog.repository.DTO;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class BlogCreationFeignClient {

    private Long userId;
    private String userName;
    private String title;
    private String content;
    private Long[] team_visibility;
    private Long[] department_visibility;
    private List<String> filesBase64Encoded;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

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

    public List<String> getFilesBase64Encoded() {
        return filesBase64Encoded;
    }

    public void setFilesBase64Encoded(List<String> filesBase64Encoded) {
        this.filesBase64Encoded = filesBase64Encoded;
    }
}
