package com.blog.repository.entity;

import com.blog.repository.auditing.Auditable;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

import java.util.Date;
import java.util.Set;

@Entity
@Table(name = "user_master")
public class User extends Auditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Size(min = 3, max = 50)
    @Column(name = "username", nullable = false, unique = true, length = 50)
    private String userName;

    @Size(min = 3, max = 50)
    @Column(name = "employee_code", nullable = false, unique = true, length = 50)
    private String empCode;
    
    @Email
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    
    @Size(min = 8)
    @Column(name = "password", nullable = false)
    private String password;

    
    @Size(min = 1, max = 100)
    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Size(min = 1, max = 100)
    @Column(name = "address", nullable = false, length = 100)
    private String address;

    @Size(min = 10, max = 10)
    @Column(name = "mobile_number", nullable = false, length = 10)
    private String mobile;

    @Column(name = "joining_date", nullable = false)
    @Temporal(TemporalType.DATE)
    private Date joiningDate;

    @Email
    @Column(name = "backup_email", nullable = false, unique = true)
    private String backupEmail;

    @Column(name = "status", nullable = false)
    private String status = "ACTIVE";

    @Column(name = "manager_id")
    private Long managerId;


    @Column(name = "post_create", nullable = false)
    private boolean postCreate = true;

    @ManyToMany
    @JoinTable(
            name = "user_department",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "department_id")
    )
    private Set<Department> departments;

    @ManyToMany
    @JoinTable(
            name = "user_team",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "team_id")
    )
    private Set<Team> teams;

    @ManyToOne
    private Role role;

    public User() {
    }

    public User(String userName, String empCode, String email, String password, String name, String address, String mobile, Date joiningDate, String backupEmail, String status, Long managerId, boolean postCreate, Set<Department> departments, Set<Team> teams, Role role) {
        this.userName = userName;
        this.empCode = empCode;
        this.email = email;
        this.password = password;
        this.name = name;
        this.address = address;
        this.mobile = mobile;
        this.joiningDate = joiningDate;
        this.backupEmail = backupEmail;
        this.status = status;
        this.managerId = managerId;
        this.postCreate = postCreate;
        this.departments = departments;
        this.teams = teams;
        this.role = role;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public @Size(min = 3, max = 50) String getUserName() {
        return userName;
    }

    public void setUserName(@Size(min = 3, max = 50) String userName) {
        this.userName = userName;
    }

    public @Email String getEmail() {
        return email;
    }

    public void setEmail(@Email String email) {
        this.email = email;
    }

    public @Size(min = 8) String getPassword() {
        return password;
    }

    public void setPassword(@Size(min = 8) String password) {
        this.password = password;
    }

    public @Size(min = 1, max = 100) String getName() {
        return name;
    }

    public void setName(@Size(min = 1, max = 100) String name) {
        this.name = name;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Long getManagerId() {
        return managerId;
    }

    public void setManagerId(Long managerId) {
        this.managerId = managerId;
    }

    public boolean isPostCreate() {
        return postCreate;
    }

    public void setPostCreate(boolean postCreate) {
        this.postCreate = postCreate;
    }

    public Set<Department> getDepartments() {
        return departments;
    }

    public void setDepartments(Set<Department> departments) {
        this.departments = departments;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public Set<Team> getTeams() {
        return teams;
    }

    public void setTeams(Set<Team> teams) {
        this.teams = teams;
    }

    public String getEmpCode() {
        return empCode;
    }

    public void setEmpCode(String empCode) {
        this.empCode = empCode;
    }

    public @Size(min = 1, max = 100) String getAddress() {
        return address;
    }

    public void setAddress(@Size(min = 1, max = 100) String address) {
        this.address = address;
    }

    public @Size(min = 10, max = 10) String getMobile() {
        return mobile;
    }

    public void setMobile(@Size(min = 10, max = 10) String mobile) {
        this.mobile = mobile;
    }

    public Date getJoiningDate() {
        return joiningDate;
    }

    public void setJoiningDate(Date joiningDate) {
        this.joiningDate = joiningDate;
    }

    public @Email String getBackupEmail() {
        return backupEmail;
    }

    public void setBackupEmail(@Email String backupEmail) {
        this.backupEmail = backupEmail;
    }
}
