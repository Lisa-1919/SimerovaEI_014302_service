package com.example.callsdataservice.models;

import jakarta.persistence.*;

import java.util.HashSet;
import java.util.Set;

@Table(name = "users")
@Entity
public class User {
    @Id@GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @Column(name="username")
    private String username;
    @Column(name="email")
    private String email;
    @Column(name="password")
    private String password;
    @Column(name="account_img_url")
    private String accountImgUrl;
    @Column(name = "language")
    private String language;

    @Transient
    private UserStatus status;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name="user_role",
            joinColumns = @JoinColumn(name="user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roleSet = new HashSet<>();

    public User(){}
    public User(Long id, String username, String email, String password) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
    }

    public User(Long id, String username, String email, String password, String accountImgUrl, String language) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.accountImgUrl = accountImgUrl;
        this.language = language;
    }

    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public String getAccountImgUrl() {
        return accountImgUrl;
    }

    public void setAccountImgUrl(String accountImgUrl) {
        this.accountImgUrl = accountImgUrl;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public Set<Role> getRoleSet() {
        return roleSet;
    }


    public void setRoleSet(Set<Role> roleSet) {
        this.roleSet = roleSet;
    }


}
