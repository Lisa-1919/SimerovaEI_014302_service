package com.example.callsdataservice.controller;

import com.example.callsdataservice.model.CallHistory;
import com.example.callsdataservice.model.Role;
import com.example.callsdataservice.model.User;
import com.example.callsdataservice.payload.request.*;
import com.example.callsdataservice.repository.RoleRepository;
import com.example.callsdataservice.repository.UserRepository;
import com.example.callsdataservice.security.jwt.JwtUtils;
import com.example.callsdataservice.service.ProfileService;
import com.example.callsdataservice.security.services.UserDetailsImpl;
import com.example.callsdataservice.security.services.UserDetailsServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
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
    private ProfileService profileService;
    @Value("${upload.path}")
    private String uploadImgPath;
    @Test
    public void testAuthenticateUser() throws Exception {
        LoginRequest loginRequest = new LoginRequest("testUser", "testPassword");

        UserDetailsImpl userDetails = new UserDetailsImpl(1L, "testUser", "testEmail", "testPassword", "en", null, new ArrayList<>());
        Authentication auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        when(authenticationManager.authenticate(any())).thenReturn(auth);
        when(jwtUtils.generateJwtToken(auth)).thenReturn("testToken");
        when(userDetailsService.loadUserByUsername("testUser")).thenReturn(userDetails);
        when(profileService.getUserCalls("testUser")).thenReturn(new ArrayList<>());

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(loginRequest)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.accessToken").value("testToken"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.username").value("testUser"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.email").value("testEmail"));
    }
    @Test
    public void testAuthenticateUser_InvalidCredentials() throws Exception {
        LoginRequest loginRequest = new LoginRequest("testUser", "wrongPassword");
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(loginRequest)))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }
    @Test
    void testRegisterUser() throws Exception {
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
    void testRegisterUser_UsernameExists() throws Exception {
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
    void testRegisterUser_EmailExists() throws Exception {
        SignupRequest signupRequest = new SignupRequest("user", "existingEmail@example.com", Collections.singleton("USER"), "password");

        when(userRepository.existsByUsername(signupRequest.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(true);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(signupRequest)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Error: Email is already taken!"));
    }
    @Test
    public void testDeleteUser() throws Exception {
        String token = "token";
        String username = "test";
        when(jwtUtils.validateJwtToken(any())).thenReturn(true);
        when(jwtUtils.extractTokenFromRequest(any())).thenReturn(token);
        when(jwtUtils.getUserNameFromJwtToken(token)).thenReturn(username);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(new User()));

        mockMvc.perform(MockMvcRequestBuilders.post("/delete"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("User deleted successfully."));
    }
    @Test
    public void testDeleteUser_NotFound() throws Exception {
        String token = "testToken";
        String username = "testUser";

        when(jwtUtils.validateJwtToken(any())).thenReturn(true);
        when(jwtUtils.extractTokenFromRequest(any())).thenReturn(token);
        when(jwtUtils.getUserNameFromJwtToken(token)).thenReturn(username);
        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

        mockMvc.perform(MockMvcRequestBuilders.post("/delete")
                        .header("Authorization", "Bearer " + token))
                .andExpect(MockMvcResultMatchers.status().isNotFound())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("User not found."));
    }
    @Test
    public void testDeleteUser_NotAuthorized() throws Exception {
        String token = "testToken";

        when(jwtUtils.validateJwtToken(any())).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders.post("/delete")
                        .header("Authorization", "Bearer " + token))
                .andExpect(MockMvcResultMatchers.status().isForbidden())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("You are not authorized to perform this action."));
    }
//    @Test
//    void testChangePassword() throws Exception {
//        ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest("testUser", "oldPassword", "newPassword");
//        String token = "token";
//        Role role = new Role(3, "USER");
//        List<Role> roles = new ArrayList<>();
//        roles.add(role);
//        UserDetailsImpl userDetails = new UserDetailsImpl(1L, "testUser", "testEmail", "newPassword", "en", null, roles);
//        Authentication auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//        when(jwtUtils.validateJwtToken(any())).thenReturn(true);
//        when(profileService.changePassword(changePasswordRequest)).thenReturn(userDetails);
//        when(jwtUtils.generateJwtToken(auth)).thenReturn(token);
//
//        mockMvc.perform(MockMvcRequestBuilders
//                        .post("/change-password")
//                        .header("Authorization", "Bearer " + token)
//                        .contentType(MediaType.APPLICATION_JSON)
//                        .content(asJsonString(changePasswordRequest)))
//                .andExpect(MockMvcResultMatchers.status().isOk())
//                .andExpect(MockMvcResultMatchers.jsonPath("$.accessToken").value(token))
//                .andExpect(MockMvcResultMatchers.jsonPath("$.username").value("testUser"))
//                .andExpect(MockMvcResultMatchers.jsonPath("$.email").value("testEmail"));
//    }
    @Test
    public void testChangePassword_MismatchedPasswords() throws Exception {
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
                        .post("/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changePasswordRequest)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest());

    }
    @Test
    public void testChangePassword_Unauthorized() throws Exception {
        ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest("username", "oldPassword", "newPassword");

        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changePasswordRequest)))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }
    @Test
    void testChangeLanguage() throws Exception {
        ChangeLanguageRequest changeLanguageRequest = new ChangeLanguageRequest("username1", "en");

        User user = new User("username1", "email1@example.com", "password");
        Optional<User> optionalUser = Optional.of(user);

        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(true);
        when(userRepository.findByUsername(changeLanguageRequest.getUsername())).thenReturn(optionalUser);
        when(userRepository.save(any(User.class))).thenReturn(user);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/change-language")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changeLanguageRequest)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Data updated"));
    }
    @Test
    void testChangeLanguage_Unauthorized() throws Exception {
        ChangeLanguageRequest changeLanguageRequest = new ChangeLanguageRequest("username", "en");

        when(jwtUtils.validateJwtToken(any(HttpServletRequest.class))).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders
                        .post("/change-language")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(changeLanguageRequest)))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Unauthorized"));
    }
    @Test
    public void testChangeImage() throws Exception {
        String token = "testToken";
        String username = "testUser";
        String imageUrl = "testImageUrl";
        MockMultipartFile image = new MockMultipartFile("image", "test.jpg", MediaType.IMAGE_JPEG_VALUE, "test image content".getBytes());

        User user = new User();
        user.setUsername(username);
        user.setImageUrl(imageUrl);

        when(jwtUtils.validateJwtToken(any())).thenReturn(true);
        when(jwtUtils.extractTokenFromRequest(any())).thenReturn(token);
        when(jwtUtils.getUserNameFromJwtToken(token)).thenReturn(username);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));
        when(profileService.uploadImage(any(), any())).thenReturn(user);

        mockMvc.perform(MockMvcRequestBuilders.multipart("/upload-image")
                        .file(image)
                        .header("Authorization", "Bearer " + token))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(imageUrl));
    }
    @Test
    public void testChangeImage_UserNotFound() throws Exception {
        String token = "testToken";
        String username = "testUser";
        MockMultipartFile image = new MockMultipartFile("image", "test.jpg", MediaType.IMAGE_JPEG_VALUE, "test image content".getBytes());

        when(jwtUtils.validateJwtToken(any())).thenReturn(true);
        when(jwtUtils.extractTokenFromRequest(any())).thenReturn(token);
        when(jwtUtils.getUserNameFromJwtToken(token)).thenReturn(username);
        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

        mockMvc.perform(MockMvcRequestBuilders.multipart("/upload-image")
                        .file(image)
                        .header("Authorization", "Bearer " + token))
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Something went wrong"));
    }
    @Test
    public void testChangeImage_Unauthorized() throws Exception {
        String token = "testToken";
        MockMultipartFile image = new MockMultipartFile("image", "test.jpg", MediaType.IMAGE_JPEG_VALUE, "test image content".getBytes());

        when(jwtUtils.validateJwtToken(any())).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders.multipart("/upload-image")
                        .file(image)
                        .header("Authorization", "Bearer " + token))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Unauthorized"));
    }
    @Test
    public void testGetImage() throws Exception {
        String imageName = "default.jpg";
        String imagePath = uploadImgPath + imageName;
        byte[] imageBytes = Files.readAllBytes(Paths.get(imagePath));

        mockMvc.perform(MockMvcRequestBuilders.get("/images/" + imageName))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().bytes(imageBytes));
    }

    @Test
    public void testSaveCallInfo() throws Exception {
        SaveCallRequest saveCallRequest = new SaveCallRequest("roomId",
                LocalDateTime.of(2024, 5, 10, 10,15,32),
                LocalDateTime.of(2024, 5, 10, 10,30,32), "en");
        String token = "testToken";
        String username = "testUser";
        User user = new User();
        user.setUsername(username);
        List<CallHistory> calls = new ArrayList<>();

        when(jwtUtils.validateJwtToken(any())).thenReturn(true);
        when(jwtUtils.extractTokenFromRequest(any())).thenReturn(token);
        when(jwtUtils.getUserNameFromJwtToken(token)).thenReturn(username);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));
        when(profileService.getUserCalls(username)).thenReturn(calls);

        mockMvc.perform(MockMvcRequestBuilders.post("/save-call")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dateTimeAsJsonString(saveCallRequest)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(new ObjectMapper().writeValueAsString(calls)));
    }

    @Test
    public void testSaveCallInfo_UserNotFound() throws Exception {
        SaveCallRequest saveCallRequest = new SaveCallRequest("roomId",
                LocalDateTime.of(2024, 5, 10, 10,15,32),
                LocalDateTime.of(2024, 5, 10, 10,30,32), "en");
        String token = "testToken";
        String username = "testUser";

        when(jwtUtils.validateJwtToken(any())).thenReturn(true);
        when(jwtUtils.extractTokenFromRequest(any())).thenReturn(token);
        when(jwtUtils.getUserNameFromJwtToken(token)).thenReturn(username);
        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

        mockMvc.perform(MockMvcRequestBuilders.post("/save-call")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dateTimeAsJsonString(saveCallRequest)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Something went wrong"));
    }

    @Test
    public void testSaveCallInfo_Unauthorized() throws Exception {
        SaveCallRequest saveCallRequest = new SaveCallRequest("roomId",
                LocalDateTime.of(2024, 5, 10, 10,15,32),
                LocalDateTime.of(2024, 5, 10, 10,30,32), "en");
        String token = "testToken";

        when(jwtUtils.validateJwtToken(any())).thenReturn(false);

        mockMvc.perform(MockMvcRequestBuilders.post("/save-call")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dateTimeAsJsonString(saveCallRequest)))
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

    private static String dateTimeAsJsonString(Object object) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());
            return mapper.writeValueAsString(object);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
