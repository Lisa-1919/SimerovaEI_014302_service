package com.example.callsdataservice.service;

import com.example.callsdataservice.model.User;
import com.example.callsdataservice.payload.request.ChangePasswordRequest;
import com.example.callsdataservice.repository.UserRepository;
import com.example.callsdataservice.security.jwt.JwtUtils;
import com.example.callsdataservice.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.UUID;

@Service
public class ProfileService {
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtUtils jwtUtils;
    @Value("${upload.path}")
    private String uploadImgPath;

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

    public  User uploadImage(MultipartFile image, User user){
        if (image != null) {
            String resultImgName = UUID.randomUUID() + "." + image.getOriginalFilename();
            try {
                image.transferTo(new File(uploadImgPath + resultImgName));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            user.setImageUrl(resultImgName);
            return userRepository.save(user);
        } return user;
    }

}
