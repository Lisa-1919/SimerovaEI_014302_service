package com.example.callsdataservice.controllers;

import com.example.callsdataservice.models.Role;
import com.example.callsdataservice.models.User;
import com.example.callsdataservice.payload.request.*;
import com.example.callsdataservice.payload.response.JwtResponse;
import com.example.callsdataservice.payload.response.MessageResponse;
import com.example.callsdataservice.repository.RoleRepository;
import com.example.callsdataservice.repository.UserRepository;
import com.example.callsdataservice.security.jwt.JwtUtils;
import com.example.callsdataservice.security.services.UserDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.*;
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
                userDetails.getImgUrl(),
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
//                    case "mod":
//                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
//                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                        roles.add(modRole);
//
//                        break;
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
        String token = jwtUtils.extractTokenFromRequest(request);
        if (token != null && jwtUtils.validateJwtToken(token)) {
            return ResponseEntity
                    .ok()
                    .body(new MessageResponse("logout"));
        }
        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Something went wrong"));
    }

    @CrossOrigin(origins = "*")
    @PostMapping("/delete")
    public ResponseEntity<?> delete(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);
        if (token != null && jwtUtils.validateJwtToken(token)) {
            String username = jwtUtils.getUserNameFromJwtToken(token);
            User user = userRepository.findByUsername(username).orElse(null);
            userRepository.delete(user);
            return ResponseEntity
                    .ok()
                    .body(new MessageResponse("deleted"));
        }
        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Something went wrong"));
    }

    @PostMapping("/changepassword")
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequest changePasswordRequest, HttpServletRequest httpServletRequest) {
        String token = jwtUtils.extractTokenFromRequest(httpServletRequest);
        if (token != null && jwtUtils.validateJwtToken(token)) {
            String username = changePasswordRequest.getUsername();
            String oldPassword = changePasswordRequest.getOldPassword();
            String newPassword = changePasswordRequest.getNewPassword();

            Optional<User> optionalUser = userRepository.findByUsername(username);
            if (optionalUser.isPresent()) {
                User user = optionalUser.get();
                if (encoder.matches(oldPassword, user.getPassword())) {
                    String encodedNewPassword = encoder.encode(newPassword);
                    user.setPassword(encodedNewPassword);
                    userRepository.save(user);

                    // Retrieve the updated UserDetails object
                    UserDetailsImpl userDetails = new UserDetailsImpl(user);

                    // Generate a new token
                    Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    String newToken = jwtUtils.generateJwtToken(authentication);
                    List<String> roles = userDetails.getAuthorities().stream()
                            .map(item -> item.getAuthority())
                            .collect(Collectors.toList());

                    return ResponseEntity.ok(new JwtResponse(newToken,
                            userDetails.getId(),
                            userDetails.getUsername(),
                            userDetails.getEmail(),
                            userDetails.getImgUrl(),
                            userDetails.getLanguage(),
                            roles));
                }
            }
        }

        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Something went wrong"));
    }


    @PostMapping("/changelanguage")
    public ResponseEntity<?> changeLanguage(@Valid @RequestBody ChangeLanguageRequest changeLanguageRequest, HttpServletRequest httpServletRequest) {
        String token = jwtUtils.extractTokenFromRequest(httpServletRequest);
        if (token != null && jwtUtils.validateJwtToken(token)) {
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
        }
        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Something went wrong"));
    }

    @CrossOrigin(origins = "*")
    @PostMapping("/upload_img")
    public ResponseEntity<?> uploadImage(@RequestParam("image") MultipartFile image, HttpServletRequest httpServletRequest) {
        String token = jwtUtils.extractTokenFromRequest(httpServletRequest);
        if (token != null && jwtUtils.validateJwtToken(token)) {
            String username = jwtUtils.getUserNameFromJwtToken(token);
            User user = userRepository.findByUsername(username).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found");
            }
            // Check if image is present
            if (image != null) {
                // Generate a unique filename for the image
                String resultImgName = UUID.randomUUID() + "." + image.getOriginalFilename();
                try {
                    // Save the image to a specific directory
                    image.transferTo(new File("src/main/resources/uploads/" + resultImgName));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                // Update the user's accountImgUrl with the new image filename
                user.setAccountImgUrl(resultImgName);
                userRepository.save(user);
                return ResponseEntity
                        .ok()
                        .body(new MessageResponse("Data updated"));
            }
        }
        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Something went wrong"));
    }

}