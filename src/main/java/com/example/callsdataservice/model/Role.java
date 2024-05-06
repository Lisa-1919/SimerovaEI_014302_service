package com.example.callsdataservice.model;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;

@Table(name = "roles")
@Entity
public class Role implements GrantedAuthority {
    @Id@GeneratedValue(strategy = GenerationType.AUTO)
    private int id;
    @Column(name = "name")
    private String name;

    public Role() {
    }

    public Role(int id, String name) {
        this.id = id;
        this.name = name;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getAuthority() {
        return name;
    }
}
