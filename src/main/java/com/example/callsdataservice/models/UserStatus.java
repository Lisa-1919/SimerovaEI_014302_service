package com.example.callsdataservice.models;

public enum UserStatus {
    ONLINE("online"),
    OFFLINE("offline");
    private String status;

    UserStatus(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
