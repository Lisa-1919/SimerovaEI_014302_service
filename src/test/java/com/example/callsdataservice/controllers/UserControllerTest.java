package com.example.callsdataservice.controllers;

import com.example.callsdataservice.models.Role;
import com.example.callsdataservice.models.User;
import com.example.callsdataservice.payload.request.*;
import com.example.callsdataservice.repository.RoleRepository;
import com.example.callsdataservice.repository.UserRepository;
import com.example.callsdataservice.security.jwt.AuthTokenFilter;
import com.example.callsdataservice.security.jwt.JwtUtils;
import com.example.callsdataservice.services.ProfileService;
import com.example.callsdataservice.security.services.UserDetailsImpl;
import com.example.callsdataservice.security.services.UserDetailsServiceImpl;
import com.example.callsdataservice.services.EmailService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import okhttp3.Response;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserRepository userRepository;
    @MockBean
    private RoleRepository roleRepository;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private UserDetailsServiceImpl userDetailsService;

    @MockBean
    private AuthenticationManager authenticationManager;

    @Mock
    private PasswordEncoder encoder;

    @MockBean
    private EmailService emailService;
    @MockBean
    private ProfileService profileService;

    @Test
    void authenticateUser() throws Exception {
        LoginRequest loginRequest = new LoginRequest("username1", "password");

        Authentication authentication = new UsernamePasswordAuthenticationToken("username1", "password");

        String jwt = "your_generated_jwt_token";

        List<Role> roles = new ArrayList<>();
        roles.add(new Role(3, "USER"));
        UserDetailsImpl userDetails = new UserDetailsImpl(502L, "username1", "email1@example.com", encoder.encode("password"), "ru", roles);

        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(jwtUtils.generateJwtToken(authentication)).thenReturn(jwt);
        when(userDetailsService.loadUserByUsername("username")).thenReturn(userDetails);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(loginRequest)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.jwt").value(jwt))
                .andExpect(MockMvcResultMatchers.jsonPath("$.id").value(userDetails.getId()))
                .andExpect(MockMvcResultMatchers.jsonPath("$.username").value(userDetails.getUsername()))
                .andExpect(MockMvcResultMatchers.jsonPath("$.email").value(userDetails.getEmail()))
                .andExpect(MockMvcResultMatchers.jsonPath("$.language").value(userDetails.getLanguage()))
                .andExpect(MockMvcResultMatchers.jsonPath("$.roles").isArray());
    }

    @Test
    void registerUser_Ok() throws Exception {
        SignupRequest signupRequest = new SignupRequest("username", "email3@example.com", Collections.singleton("USER"), "oldPassword");

        when(userRepository.existsByUsername(signupRequest.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(new Role(3, "USER")));
        when(encoder.encode(signupRequest.getPassword())).thenReturn("encodedPassword");

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(signupRequest)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("User registered successfully!"));
    }

    @Test
    void registerUser_UsernameExists() throws Exception {
        SignupRequest signupRequest = new SignupRequest("existingUser", "email@example.com", Collections.singleton("USER"), "password");

        when(userRepository.existsByUsername(signupRequest.getUsername())).thenReturn(true);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(signupRequest)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Error: Username is already taken!"));
    }

    @Test
    void registerUser_EmailExists() throws Exception {
        SignupRequest signupRequest = new SignupRequest("username", "existingEmail@example.com", Collections.singleton("USER"), "password");

        when(userRepository.existsByUsername(signupRequest.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(true);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(signupRequest)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Error: Email is already in use!"));
    }


    @Test
    public void delete_Ok() throws Exception {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VybmFtZTMiLCJpYXQiOjE3MDkwMjkxOTQsImV4cCI6MTcwOTEwNTQ5NH0.xcS9r_pL7KyEjulaeErr3Fj-UUpzGtUjqE5HduXLlPA";
        String username = "username3";
        User user = new User();
        user.setUsername(username);
        when(jwtUtils.extractTokenFromRequest(request)).thenReturn(token);
        when(jwtUtils.validateJwtToken(request)).thenReturn(true);
        when(jwtUtils.getUserNameFromJwtToken(token)).thenReturn(username);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));

        mockMvc.perform(MockMvcRequestBuilders.post("/delete"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("deleted"));
    }

    @Test
    public void delete_Unauthorized() throws Exception {
        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders.post("/delete"))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Unauthorized"));
    }

    @Test
    void changePassword_Ok() throws Exception {
        ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest("username", "oldPassword", "newPassword");
        String username = changePasswordRequest.getUsername();
        String oldPassword = changePasswordRequest.getOldPassword();
        String newPassword = changePasswordRequest.getNewPassword();
        User user = new User();
        user.setUsername(username);
        user.setPassword(encoder.encode(oldPassword));
        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(true);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));
        when(encoder.matches(oldPassword, user.getPassword())).thenReturn(true);
        UserDetailsImpl userDetails = profileService.changePassword(new ChangePasswordRequest(username, oldPassword, newPassword));
        mockMvc.perform(MockMvcRequestBuilders
                        .post("/changepassword")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changePasswordRequest)))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

    @Test
    public void changePassword_MismatchedPasswords() throws Exception {
        ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest("username", "oldPassword", "wrongPassword");
        String username = changePasswordRequest.getUsername();
        String oldPassword = changePasswordRequest.getOldPassword();
        User user = new User();
        user.setUsername(username);
        user.setPassword(encoder.encode(oldPassword));
        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(true);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));
        when(encoder.matches(oldPassword, user.getPassword())).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/changepassword")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changePasswordRequest)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest());

    }

    @Test
    public void changePassword_Unauthorized() throws Exception {
        ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest("username", "oldPassword", "newPassword");

        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/changepassword")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changePasswordRequest)))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    void changeLanguage_Ok() throws Exception {
        ChangeLanguageRequest changeLanguageRequest = new ChangeLanguageRequest("username1", "en");

        User user = new User("username1", "email1@example.com", "password");
        Optional<User> optionalUser = Optional.of(user);

        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(true);
        when(userRepository.findByUsername(changeLanguageRequest.getUsername())).thenReturn(optionalUser);
        when(userRepository.save(any(User.class))).thenReturn(user);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/changelanguage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changeLanguageRequest)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Data updated"));
    }

    @Test
    void changeLanguage_Unauthorized() throws Exception {
        ChangeLanguageRequest changeLanguageRequest = new ChangeLanguageRequest("username", "en");

        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/changelanguage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changeLanguageRequest)))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Unauthorized"));
    }

    @Test
    void sendEmail_Ok() throws Exception {
        SendEmailRequest sendEmailRequest = new SendEmailRequest("lizasimerova438@gmail.com", "Hello, world!");

        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(true);
        when(jwtUtils.extractTokenFromRequest(any(HttpServletRequest.class))).thenReturn("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsaXNhIiwiaWF0IjoxNzA5MDI3ODEzLCJleHAiOjE3MDkxMDQxMTN9.QFAuWR1hW3OipXmpaTT_tunDaE3NvPyHLGugps5ME5Q");
        when(jwtUtils.getUserNameFromJwtToken("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsaXNhIiwiaWF0IjoxNzA5MDI3ODEzLCJleHAiOjE3MDkxMDQxMTN9.QFAuWR1hW3OipXmpaTT_tunDaE3NvPyHLGugps5ME5Q")).thenReturn("lisa");
        when(userRepository.findByUsername("lisa")).thenReturn(Optional.of(new User()));
        when(emailService.sendEmail(any(SendEmailRequest.class), anyString())).thenReturn(true);
        mockMvc.perform(MockMvcRequestBuilders
                        .post("/sendemail")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(sendEmailRequest)))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }


    @Test
    public void sendEmail_Unauthorized() throws Exception {
        when(jwtUtils.validateJwtToken(any())).thenReturn(false);

        SendEmailRequest sendEmailRequest = new SendEmailRequest();
        sendEmailRequest.setEmailTo("recipient@example.com");
        sendEmailRequest.setMessage("Hello, this is a test email.");

        mockMvc.perform(MockMvcRequestBuilders.post("/sendemail")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(sendEmailRequest)))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());

        verify(emailService, never()).sendEmail(any(), anyString());
    }

    @Test
    public void sendEmail_BadRequest() throws Exception {
        SendEmailRequest sendEmailRequest = new SendEmailRequest(null, "Hello, this is a test email.");
        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(true);

        mockMvc.perform(MockMvcRequestBuilders.post("/sendemail")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(sendEmailRequest)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Something went wrong"));

        verifyNoInteractions(emailService);
    }

    private static String asJsonString(Object object) {
        try {
            return new ObjectMapper().writeValueAsString(object);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
