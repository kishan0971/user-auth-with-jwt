package com.blog.repository.entity;

import com.blog.repository.auditing.Auditable;
import jakarta.persistence.*;

@Entity
@Table(name = "team")
public class Team extends Auditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name", unique = true, nullable = false)
    private String name;

    @Column(name = "description", length = 200)
    private String description;

    // Default constructor
    public Team(){

    }

    // parametrized constructor

    public Team(String name, String description) {
        this.name = name;
        this.description=description;
    }

    public Team(String name) {
        super();
    }

    // getters and setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
