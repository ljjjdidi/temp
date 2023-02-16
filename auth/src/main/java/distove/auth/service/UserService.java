package distove.auth.service;


import distove.auth.dto.request.JoinRequest;
import distove.auth.dto.request.LoginRequest;
import distove.auth.dto.request.UpdateNicknameRequest;
import distove.auth.dto.request.UpdateProfileImgRequest;
import distove.auth.dto.response.TokenResponse;
import distove.auth.dto.response.UserResponse;
import distove.auth.entity.User;
import distove.auth.exception.DistoveException;
import distove.auth.repoisitory.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

import static distove.auth.exception.ErrorCode.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final StorageService storageService;

    @Value("${default.img.address}")
    private String defaultImgUrl;

    public UserResponse join(JoinRequest request) {
        String profileImgUrl;

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DistoveException(DUPLICATE_EMAIL);
        }

        if (request.getProfileImg() == null || request.getProfileImg().isEmpty()) {
            profileImgUrl = defaultImgUrl;
        } else {
            profileImgUrl = storageService.uploadToS3(request.getProfileImg());
        }

        User user = new User(request.getEmail(), bCryptPasswordEncoder.encode(request.getPassword()), request.getNickname(), profileImgUrl);
        userRepository.save(user);

        return UserResponse.of(user.getId(), user.getNickname(), user.getProfileImgUrl());
    }

    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new DistoveException(ACCOUNT_NOT_FOUND));

        if (!bCryptPasswordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new DistoveException(INVAILD_PASSWORD);
        }

        String accessToken = jwtTokenProvider.createToken(user.getId(), "AT");
        String refreshToken = jwtTokenProvider.createToken(user.getId(), "RT");

        String cookie = jwtTokenProvider.createTokenCookie(refreshToken).toString();
        user.updateRefreshToken(refreshToken);
        userRepository.save(user);

        return TokenResponse.of(accessToken, cookie);
    }

    public UserResponse logout(String token) {
        User user = userRepository.findById(jwtTokenProvider.getUserId(token))
                .orElseThrow(() -> new DistoveException(ACCOUNT_NOT_FOUND));

        user.updateRefreshToken(null);
        userRepository.save(user);
        return UserResponse.of(user.getId(), user.getNickname(), user.getEmail());
    }

    public UserResponse getUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new DistoveException(ACCOUNT_NOT_FOUND));
        return UserResponse.of(user.getId(), user.getNickname(), user.getProfileImgUrl());
    }

    public List<UserResponse> getUsers(List<Long> userIds) {
        List<UserResponse> users = new ArrayList<>();

        for (Long userId : userIds) {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new DistoveException(ACCOUNT_NOT_FOUND));
            users.add(UserResponse.of(user.getId(), user.getNickname(), user.getProfileImgUrl()));
        }
        return users;
    }

    public UserResponse updateNickname(String token, UpdateNicknameRequest request) {
        User user = userRepository.findById(jwtTokenProvider.getUserId(token))
                .orElseThrow(() -> new DistoveException(ACCOUNT_NOT_FOUND));

        user.updateNickname(request.getNickname());
        userRepository.save(user);
        return UserResponse.of(user.getId(), user.getNickname(), user.getProfileImgUrl());
    }

    public UserResponse updateProfileImg(String token, UpdateProfileImgRequest request) {
        String profileImgUrl;
        User user = userRepository.findById(jwtTokenProvider.getUserId(token))
                .orElseThrow(() -> new DistoveException(ACCOUNT_NOT_FOUND));

        if (request.getProfileImg() == null || request.getProfileImg().isEmpty()) {
            profileImgUrl = defaultImgUrl;
            if (user.getProfileImgUrl().equals(profileImgUrl)) {
                return UserResponse.of(user.getId(), user.getNickname(), user.getProfileImgUrl());
            }
        } else {
            profileImgUrl = storageService.uploadToS3(request.getProfileImg());
        }

        storageService.deleteFile(user.getProfileImgUrl());
        user.updateProfileImgUrl(profileImgUrl);
        userRepository.save(user);
        return UserResponse.of(user.getId(), user.getNickname(), user.getProfileImgUrl());

    }

    public TokenResponse reissue(String token) {
        if (jwtTokenProvider.getTypeOfToken(token).equals("RT")) {
            String cookie = jwtTokenProvider.createTokenCookie(token).toString();
            return TokenResponse.of(jwtTokenProvider.createToken(getUserIdFromDatabase(token), "AT"), cookie);
        }

        throw new DistoveException(NOT_REFRESH_TOKEN);
    }

    //refreshToken
    public Long getUserIdFromDatabase(String token) {
        User user = userRepository.findById(jwtTokenProvider.getUserId(token))
                .orElseThrow(() -> new DistoveException(ACCOUNT_NOT_FOUND));
        return user.getId();
    }

}