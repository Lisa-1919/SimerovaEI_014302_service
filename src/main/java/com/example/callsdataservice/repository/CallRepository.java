package com.example.callsdataservice.repository;

import com.example.callsdataservice.model.Call;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CallRepository extends JpaRepository<Call, Long> {
}
