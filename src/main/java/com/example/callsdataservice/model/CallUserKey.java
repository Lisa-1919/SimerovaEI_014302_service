package com.example.callsdataservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Embeddable
public class CallUserKey implements Serializable {

    @Column(name = "call_id")
    private Long callId;

    @Column(name = "user_id")
    private Long userId;

}
