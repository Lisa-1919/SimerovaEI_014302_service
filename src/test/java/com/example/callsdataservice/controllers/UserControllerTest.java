package com.example.callsdataservice.controllers;

import com.example.callsdataservice.security.services.UserDetailsServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(UserController.class)
class UserControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockBean
    UserDetailsServiceImpl userDetailsService;

    @Test
    void all() throws Exception {
    }

    @Test
    void authenticateUser() {
    }

    @Test
    void registerUser() {
    }

    @Test
    void logout() {
    }

    @Test
    void delete() {
    }

    @Test
    void changePassword() {
    }

    @Test
    void changeLanguage() {
    }
}