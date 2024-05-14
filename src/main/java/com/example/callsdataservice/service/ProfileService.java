package com.example.callsdataservice.service;

import com.example.callsdataservice.model.Call;
import com.example.callsdataservice.model.CallHistory;
import com.example.callsdataservice.model.CallUser;
import com.example.callsdataservice.model.User;
import com.example.callsdataservice.payload.request.ChangePasswordRequest;
import com.example.callsdataservice.payload.request.SaveCallRequest;
import com.example.callsdataservice.repository.CallRepository;
import com.example.callsdataservice.repository.CallUserRepository;
import com.example.callsdataservice.repository.UserRepository;
import com.example.callsdataservice.security.jwt.JwtUtils;
import com.example.callsdataservice.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class ProfileService {
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CallRepository callRepository;
    @Autowired
    private CallUserRepository callUserRepository;
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

    public User uploadImage(MultipartFile image, User user) {
        if (image != null) {
            String previousImageName = user.getImageUrl();

            if (previousImageName != null && !previousImageName.isEmpty()) {
                File previousImageFile = new File(uploadImgPath + previousImageName);
                if (previousImageFile.exists()) {
                    if (previousImageFile.delete()) {
                        System.out.println("Previous image deleted successfully.");
                    } else {
                        System.out.println("Failed to delete previous image.");
                    }
                }
            }

            String resultImgName = UUID.randomUUID() + "." + image.getOriginalFilename();
            try {
                image.transferTo(new File(uploadImgPath + resultImgName));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            user.setImageUrl(resultImgName);
            return userRepository.save(user);
        }
        return user;
    }

    public List<CallHistory> getUserCalls(String username){
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            return user.getCallUsers().stream()
                    .map(callUser -> new CallHistory(
                            callUser.getCall().getId(),
                            callUser.getCall().getStartDate(),
                            callUser.getCall().getEndDate(),
                            callUser.getCall().getRoomId(),
                            callUser.getLanguage()))
                    .sorted(Comparator.comparing(CallHistory::getStartDate))
                    .collect(Collectors.toList());
        } else {
            return null;
        }
    }

    public void saveCall(User user, SaveCallRequest saveCallRequest){
        Call call = new Call();
        call.setStartDate(saveCallRequest.getStartTime());
        call.setEndDate(saveCallRequest.getEndTime());
        call.setRoomId(saveCallRequest.getRoomId());
        callRepository.save(call);

        CallUser callUser = new CallUser();
        callUser.setUser(user);
        callUser.setCall(call);
        callUser.setLanguage(saveCallRequest.getLanguage());
        callUserRepository.save(callUser);

        user.getCallUsers().add(callUser);
        userRepository.save(user);
    }
}
