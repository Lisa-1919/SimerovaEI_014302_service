package com.example.callsdataservice.controllers;

import com.example.callsdataservice.models.Role;
import com.example.callsdataservice.models.User;
import com.example.callsdataservice.payload.request.ChangeLanguageRequest;
import com.example.callsdataservice.payload.request.LoginRequest;
import com.example.callsdataservice.payload.request.SignupRequest;
import com.example.callsdataservice.repository.RoleRepository;
import com.example.callsdataservice.repository.UserRepository;
import com.example.callsdataservice.security.jwt.AuthTokenFilter;
import com.example.callsdataservice.security.jwt.JwtUtils;
import com.example.callsdataservice.security.services.UserDetailsImpl;
import com.example.callsdataservice.security.services.UserDetailsServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
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
import static org.mockito.Mockito.when;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private UserDetailsServiceImpl userDetailsService;

    @MockBean
    private AuthenticationManager authenticationManager;
    @Mock
    private AuthTokenFilter authTokenFilter;
    @Mock
    public PasswordEncoder encoder;

    @Test
    void all() throws Exception {
        List<User> users = Arrays.asList(
                new User("John"),
                new User("Jane")
        );

        when(userDetailsService.getAll()).thenReturn(users);

        mockMvc.perform(MockMvcRequestBuilders
                        .get("/all")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json("[{\"username\":\"John\"},{\"username\":\"Jane\"}]"));
    }

    @Test
    void authenticateUser() throws Exception {
        LoginRequest loginRequest = new LoginRequest("username", "password");

        Authentication authentication = new UsernamePasswordAuthenticationToken("username", "password");

        String jwt = "your_generated_jwt_token";

        List<Role> roles = new ArrayList<>();
        roles.add(new Role(1, "USER"));
        UserDetailsImpl userDetails = new UserDetailsImpl(1L, "username", "email", "language", "password", roles);

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
    void registerUser() throws Exception {
        SignupRequest signupRequest = new SignupRequest("username2", "email2@example.com", Collections.singleton("USER"), "password");

        when(userRepository.existsByUsername(signupRequest.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(new Role(1, "USER")));
        when(encoder.encode(signupRequest.getPassword())).thenReturn("encodedPassword");

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(signupRequest)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("User registered successfully!"));
    }
    @Test
    public void delete_ValidRequest_ReturnsOkResponse() throws Exception {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        String token = "token";
        String username = "username";
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
    public void delete_UnauthorizedRequest_ReturnsUnauthorizedResponse() throws Exception {
        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders.post("/delete"))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Unauthorized"));
    }

    @Test
    void changePassword() throws Exception {

    }


    @Test
    void changeLanguage_ValidRequest_ReturnsOkResponse() throws Exception {
        ChangeLanguageRequest changeLanguageRequest = new ChangeLanguageRequest("username", "en");

        User user = new User("username", "email@example.com", "password");
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
    void changeLanguage_UnauthorizedRequest_ReturnsUnauthorizedResponse() throws Exception {
        ChangeLanguageRequest changeLanguageRequest = new ChangeLanguageRequest("username", "en");

        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/changelanguage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changeLanguageRequest)))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Unauthorized"));
    }

    private static String asJsonString(Object object) {
        try {
            return new ObjectMapper().writeValueAsString(object);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
