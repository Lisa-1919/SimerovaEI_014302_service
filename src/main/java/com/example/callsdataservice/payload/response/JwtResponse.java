package com.example.callsdataservice.payload.response;

import com.example.callsdataservice.model.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.core.io.Resource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
public class JwtResponse {
    private String accessToken;
    private String type = "Bearer";
    private Long id;
    private String username;
    private String email;
    private String language;
    private String imageUrl;
    private List<String> roles;

    public JwtResponse(String accessToken, Long id, String username, String email, String language, String imageUrl, List<String> roles) {
        this.accessToken = accessToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.language = language;
        this.imageUrl = imageUrl;
        this.roles = roles;
    }

    public JwtResponse(String accessToken, Long id, String username, String email, String language, List<String> roles) {
        this.accessToken = accessToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.language = language;
        this.roles = roles;
    }
}