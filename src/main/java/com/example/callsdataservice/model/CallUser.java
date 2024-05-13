package com.example.callsdataservice.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "call_user")
public class CallUser {
    @EmbeddedId
    private CallUserKey id;

    @ManyToOne
    @MapsId("userId")
    @JoinColumn(name = "user_id")
    @JsonBackReference
    private User user;

    @ManyToOne
    @MapsId("callId")
    @JoinColumn(name = "call_id")
    @JsonBackReference
    private Call call;

    @Column(name = "language")
    private String language;
}
