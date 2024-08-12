package com.blog.repository.repository;

import com.blog.repository.entity.Team;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface TeamRepository extends JpaRepository<Team, Long> {

    Optional<Team> findByName(String name);

    @Query("SELECT t FROM Team t WHERE t.deletedAt IS NULL")
    Page<Team> findAllActive(Pageable pageable);

    @Query("SELECT t FROM Team t WHERE t.deletedAt IS NOT NULL")
    List<Team> findAllDeleted();

    @Query("SELECT t FROM Team t WHERE t.name LIKE %:name% AND t.deletedAt IS NULL")
    Page<Team> findByNameContainingIgnoreCaseActive(@Param("name") String name, Pageable pageable);

    @Query("SELECT t FROM Team t WHERE t.id = :id AND t.deletedAt IS NULL")
    Optional<Team> findByIdActive(@Param("id") Long id);

    @Modifying
    @Query("UPDATE Team t SET t.deletedAt = :deletedAt, t.deletedBy = :deletedBy WHERE t.id = :id AND t.deletedAt IS NULL")
    void softDelete(@Param("id") Long id, @Param("deletedBy") String deletedBy, @Param("deletedAt") LocalDateTime deletedAt);

    @Modifying
    @Query("UPDATE Team t SET t.deletedAt = NULL, t.deletedBy = NULL WHERE t.id = :id AND t.deletedAt IS NOT NULL")
    void restore(@Param("id") Long id);

}
