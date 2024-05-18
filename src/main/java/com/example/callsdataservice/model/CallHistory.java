package com.example.callsdataservice.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CallHistory {
    private Long callId;
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private String roomId;
    private String language;

    public CallHistory(LocalDateTime startDate, LocalDateTime endDate, String roomId, String language) {
        this.startDate = startDate;
        this.endDate = endDate;
        this.roomId = roomId;
        this.language = language;
    }
}
