package com.blog.repository.DTO;

import java.util.Date;
import java.util.Set;

public class UserRequest {

    private String email;
    private String name;
    private String empCode;
    private Long managerId;
    private Set<String> department;
    private Set<String> team;
    private String role;
    private String address;
    private String mobile;
    private String backupEmail;
    private Date joinDate;
    // Getters and setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Long getManagerId() {
        return managerId;
    }

    public void setManagerId(Long managerId) {
        this.managerId = managerId;
    }

    public Set<String> getDepartment() {
        return department;
    }

    public void setDepartment(Set<String> department) {
        this.department = department;
    }

    public String getRole() {
        return role;
    }
    public void setRole(String role) {
        this.role = role;
    }

    public Set<String> getTeam() {
        return team;
    }

    public void setTeam(Set<String> team) {
        this.team = team;
    }

    public String getEmpCode() {
        return empCode;
    }

    public void setEmpCode(String empCode) {
        this.empCode = empCode;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getMobile() {
        return mobile;
    }

    public void setMobile(String mobile) {
        this.mobile = mobile;
    }

    public String getBackupEmail() {
        return backupEmail;
    }

    public void setBackupEmail(String backupEmail) {
        this.backupEmail = backupEmail;
    }

    public Date getJoinDate() {
        return joinDate;
    }

    public void setJoinDate(Date joinDate) {
        this.joinDate = joinDate;
    }
}