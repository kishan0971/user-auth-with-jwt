package com.blog.repository.repository;

import com.blog.repository.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> , JpaSpecificationExecutor<User> {

    @Modifying
    @Query("UPDATE User e SET e.deletedBy = :deletedBy, e.deletedAt = CURRENT_TIMESTAMP, e.status='INACTIVE', e.postCreate=false WHERE e.id = :id AND e.createdBy = :deletedBy")
    void softDelete(@Param("deletedBy") String deletedBy, @Param("id") Long id);

    Optional<User> findByEmail(String email);

    User findByUserName(String username);

    @Query("SELECT e FROM User e WHERE " +
            "CONCAT(e.userName, ' ', e.empCode, ' ', e.email, ' ', e.name, ' ', e.address, ' ', e.mobile) LIKE %:keyword%")
    Page<User> searchAllColumns(@Param("keyword") String keyword, Pageable pageable);


    @Query("SELECT u.userName, d.name FROM User u " +
            "JOIN u.departments d " +
            "WHERE u.createdBy = :createdBy " +
            "AND (:departmentName IS NULL OR UPPER(d.name) LIKE UPPER(CAST(:departmentName AS text)))")
    Page<Object[]> findByDepartment(@Param("createdBy") String createdBy, @Param("departmentName") String departmentName, Pageable paging);


    @Query("SELECT u.userName, t.name FROM User u " +
            "JOIN u.teams t " +
            "WHERE u.createdBy = :createdBy " +
            "AND (:teamName IS NULL OR UPPER(t.name) LIKE UPPER(CAST(:teamName AS text)))")
    Page<Object[]> findByTeam(@Param("teamName") String teamName, @Param("createdBy") String createdBy, Pageable paging);


    @Query("SELECT u.userName, r.name FROM User u " +
            "JOIN u.role r " +
            "WHERE u.createdBy = :createdBy " +
            "AND (:roleName IS NULL OR UPPER(r.name) LIKE UPPER(CAST(:roleName AS text)))")
    Page<Object[]> findByRole(@Param("createdBy") String createdBy, @Param("roleName") String roleName, Pageable paging);


    @Query("SELECT u FROM User u where u.createdBy=:createdBy ")
    List<User> findUserCreatedBy(@Param("createdBy") String createdBy);

}