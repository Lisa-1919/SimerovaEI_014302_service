package com.example.callsdataservice.payload.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SaveCallRequest {
    private String roomId;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private String language;
}
