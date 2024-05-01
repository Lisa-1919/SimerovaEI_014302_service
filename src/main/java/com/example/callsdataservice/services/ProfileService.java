package com.example.callsdataservice.services;

import com.example.callsdataservice.models.User;
import com.example.callsdataservice.payload.request.ChangePasswordRequest;
import com.example.callsdataservice.repository.UserRepository;
import com.example.callsdataservice.security.jwt.JwtUtils;
import com.example.callsdataservice.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ProfileService {
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtUtils jwtUtils;
    public UserDetailsImpl changePassword(ChangePasswordRequest changePasswordRequest){
        String username = changePasswordRequest.getUsername();
        String oldPassword = changePasswordRequest.getOldPassword();
        String newPassword = changePasswordRequest.getNewPassword();
        Optional<User> optionalUser = userRepository.findByUsername(username);
        User user = optionalUser.get();
        if (encoder.matches(oldPassword, user.getPassword())) {
            String encodedNewPassword = encoder.encode(newPassword);
            user.setPassword(encodedNewPassword);
            userRepository.save(user);
            UserDetailsImpl userDetails = new UserDetailsImpl(user);

            return userDetails;
        } return null;
    }

}
