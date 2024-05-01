package com.example.callsdataservice.controllers;

import com.example.callsdataservice.models.Role;
import com.example.callsdataservice.models.User;
import com.example.callsdataservice.payload.request.*;
import com.example.callsdataservice.payload.response.JwtResponse;
import com.example.callsdataservice.payload.response.MessageResponse;
import com.example.callsdataservice.repository.RoleRepository;
import com.example.callsdataservice.repository.UserRepository;
import com.example.callsdataservice.security.jwt.JwtUtils;
import com.example.callsdataservice.services.ProfileService;
import com.example.callsdataservice.security.services.UserDetailsImpl;
import com.example.callsdataservice.security.services.UserDetailsServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
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

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                userDetails.getLanguage(),
                roles));
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
                    .body(new MessageResponse("Error: Email is already in use!"));
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
                switch (role) {
                    case "admin":
                        Role adminRole = (Role) roleRepository.findByName("ADMIN")
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    default:
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

    @CrossOrigin(origins = "*")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        if (jwtUtils.validateJwtToken(request)) {
            return ResponseEntity
                    .ok()
                    .body(new MessageResponse("logout"));
        }
        return ResponseEntity
                .status(401).body(new MessageResponse("Unauthorized"));
    }

    @CrossOrigin(origins = "*")
    @PostMapping("/delete")
    public ResponseEntity<?> delete(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);
        if (jwtUtils.validateJwtToken(request)) {
            String username = jwtUtils.getUserNameFromJwtToken(token);
            User user = userRepository.findByUsername(username).orElse(null);
            userRepository.delete(user);
            return ResponseEntity
                    .ok()
                    .body(new MessageResponse("deleted"));
        }
        return ResponseEntity
                .status(401).body(new MessageResponse("Unauthorized"));
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

    @PostMapping("/upload-image")
    public ResponseEntity<MessageResponse> changeImage(MultipartFile image, HttpServletRequest httpServletRequest){
        if (jwtUtils.validateJwtToken(httpServletRequest)) {
            Optional<User> optionalUser = userRepository.findByUsername(jwtUtils.getUserNameFromJwtToken(jwtUtils.extractTokenFromRequest(httpServletRequest)));
            if (optionalUser.isPresent()) {

                return ResponseEntity
                        .ok()
                        .body(new MessageResponse("Image is saved"));
            }
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Something went wrong"));
        }
        return ResponseEntity
                .status(401).body(new MessageResponse("Unauthorized"));
    }

}