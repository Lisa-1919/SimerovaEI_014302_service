package com.example.callsdataservice.payload.request;

public class SendEmailRequest {
    private String emailTo;
    private String message;

    public SendEmailRequest() {
    }

    public SendEmailRequest(String emailTo, String message) {
        this.emailTo = emailTo;
        this.message = message;
    }

    public String getEmailTo() {
        return emailTo;
    }

    public void setEmailTo(String emailTo) {
        this.emailTo = emailTo;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
