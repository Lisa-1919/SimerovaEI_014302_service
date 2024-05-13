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
}
