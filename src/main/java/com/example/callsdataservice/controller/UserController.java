package com.example.callsdataservice.controller;

import com.example.callsdataservice.model.*;
import com.example.callsdataservice.payload.request.*;
import com.example.callsdataservice.payload.response.JwtResponse;
import com.example.callsdataservice.payload.response.MessageResponse;
import com.example.callsdataservice.repository.RoleRepository;
import com.example.callsdataservice.repository.UserRepository;
import com.example.callsdataservice.security.jwt.JwtUtils;
import com.example.callsdataservice.security.services.UserDetailsImpl;
import com.example.callsdataservice.security.services.UserDetailsServiceImpl;
import com.example.callsdataservice.service.ProfileService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
public class UserController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private ProfileService profileService;

    @Value("${upload.path}")
    private String uploadImgPath;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        List<CallHistory> calls = profileService.getUserCalls(userDetails.getUsername());
        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                userDetails.getLanguage(),
                userDetails.getImageUrl(),
                roles,
                calls));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already taken!"));
        }
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = (Role) roleRepository.findByName("USER")
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                if (role.equals("admin")) {
                    Role adminRole = (Role) roleRepository.findByName("ADMIN")
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(adminRole);
                } else {
                    Role userRole = (Role) roleRepository.findByName("USER")
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(userRole);
                }
            });
        }

        user.setRoleSet(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/delete")
    public ResponseEntity<?> delete(HttpServletRequest request) {
        if (jwtUtils.validateJwtToken(request)) {
            String username = jwtUtils.getUserNameFromJwtToken(jwtUtils.extractTokenFromRequest(request));
            return userRepository.findByUsername(username)
                    .map(user -> {
                        userRepository.delete(user);
                        return ResponseEntity.ok(new MessageResponse("User deleted successfully."));
                    })
                    .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(new MessageResponse("User not found.")));
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new MessageResponse("You are not authorized to perform this action."));
    }


    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequest changePasswordRequest, HttpServletRequest httpServletRequest) {
        if (jwtUtils.validateJwtToken(httpServletRequest)) {
            UserDetailsImpl userDetails = profileService.changePassword(changePasswordRequest);
            if (userDetails != null) {
                Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                String newToken = jwtUtils.generateJwtToken(authentication);

                List<String> roles = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList());
                return ResponseEntity.ok(new JwtResponse(newToken,
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        userDetails.getLanguage(),
                        userDetails.getImageUrl(),
                        roles));
            }
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Something went wrong"));
        }
        return ResponseEntity
                .status(401).body(new MessageResponse("Unauthorized"));
    }

    @PostMapping("/change-language")
    public ResponseEntity<?> changeLanguage(@Valid @RequestBody ChangeLanguageRequest
                                                    changeLanguageRequest, HttpServletRequest httpServletRequest) {
        if (jwtUtils.validateJwtToken(httpServletRequest)) {
            String username = changeLanguageRequest.getUsername();
            String language = changeLanguageRequest.getLanguage();
            Optional<User> optionalUser = userRepository.findByUsername(username);
            if (optionalUser.isPresent()) {
                User user = optionalUser.get();
                user.setLanguage(language);
                userRepository.save(user);
                return ResponseEntity
                        .ok()
                        .body(new MessageResponse("Data updated"));
            }
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Something went wrong"));
        }
        return ResponseEntity
                .status(401).body(new MessageResponse("Unauthorized"));
    }

    @PostMapping(value = "/upload-image", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> changeImage(@RequestParam("image") MultipartFile image, HttpServletRequest httpServletRequest) throws ServletException, IOException {
        if (jwtUtils.validateJwtToken(httpServletRequest)) {
            Optional<User> optionalUser = userRepository.findByUsername(jwtUtils.getUserNameFromJwtToken(jwtUtils.extractTokenFromRequest(httpServletRequest)));
            if (optionalUser.isPresent()) {
                User user = optionalUser.get();
                user = profileService.uploadImage(image, user);
                return ResponseEntity.ok().body(user.getImageUrl());
            }
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Something went wrong"));
        }
        return ResponseEntity
                .status(401).body(new MessageResponse("Unauthorized"));
    }

    @GetMapping(value = "/images/{imageName}", produces = MediaType.IMAGE_JPEG_VALUE)
    public byte[] getImage(@PathVariable String imageName) throws IOException {
        String path = uploadImgPath + imageName;
        File imageFile = new File(path);
        InputStream in = new FileInputStream(imageFile);
        return IOUtils.toByteArray(in);
    }

    @PostMapping("/save-call")
    public ResponseEntity<?> saveCallInfo(@Valid @RequestBody SaveCallRequest saveCallRequest, HttpServletRequest httpServletRequest){
        if (jwtUtils.validateJwtToken(httpServletRequest)) {
            Optional<User> optionalUser = userRepository.findByUsername(jwtUtils.getUserNameFromJwtToken(jwtUtils.extractTokenFromRequest(httpServletRequest)));
            if (optionalUser.isPresent()) {
                profileService.saveCall(optionalUser.get(), saveCallRequest);
                List<CallHistory> calls = profileService.getUserCalls(optionalUser.get().getUsername());
                return ResponseEntity.ok().body(calls);
            }
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Something went wrong"));
        }
        return ResponseEntity
                .status(401).body(new MessageResponse("Unauthorized"));
    }
}