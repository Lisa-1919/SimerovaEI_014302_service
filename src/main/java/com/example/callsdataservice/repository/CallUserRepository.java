package com.example.callsdataservice.repository;

import com.example.callsdataservice.model.CallUser;
import com.example.callsdataservice.model.CallUserKey;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CallUserRepository extends JpaRepository<CallUser, CallUserKey> {
}
