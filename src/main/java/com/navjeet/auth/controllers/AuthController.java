package com.navjeet.auth.controllers;

import com.navjeet.auth.dtos.LoginRequest;
import com.navjeet.auth.dtos.TokenResponse;
import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.entities.RefreshToken;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.mappers.UserMapper;
import com.navjeet.auth.repositories.RefreshTokenRepository;
import com.navjeet.auth.repositories.UserRepository;
import com.navjeet.auth.security.JwtService;
import com.navjeet.auth.services.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final UserMapper userMapper;
    private final RefreshTokenRepository refreshTokenRepository;


    private Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));

        } catch (Exception e) {
            throw new BadCredentialsException("Invalid email or password!!");

        }
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) {

        Authentication authenticate = authenticate(loginRequest);
        User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(() -> new BadCredentialsException("User not found with given email id"));
        if (!user.isEnable()) {
            throw new DisabledException("User account is disabled");
        }

        String jti = UUID.randomUUID().toString();
        var refreshTokenObject = RefreshToken.builder().jti(jti).user(user).createdAt(Instant.now()).expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds())).revoked(false).build();
        refreshTokenRepository.save(refreshTokenObject);


        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenObject.getJti());
        TokenResponse tokenResponse = TokenResponse.of(accessToken, refreshToken, jwtService.getAccessTtlSeconds(), userMapper.toDto(user));
        return ResponseEntity.ok(tokenResponse);


    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }
}
