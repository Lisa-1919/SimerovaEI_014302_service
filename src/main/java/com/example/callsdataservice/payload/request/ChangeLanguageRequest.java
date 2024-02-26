package com.example.callsdataservice.payload.request;

import jakarta.validation.constraints.NotBlank;

public class ChangeLanguageRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String language;

    public ChangeLanguageRequest(String username, String language) {
        this.username = username;
        this.language = language;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }
}
