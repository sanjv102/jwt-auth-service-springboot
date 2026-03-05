package com.jwt.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.auth.dto.AuthResponse;
import com.jwt.auth.dto.ForgotPasswordRequest;
import com.jwt.auth.dto.LoginRequest;
import com.jwt.auth.dto.LogoutRequest;
import com.jwt.auth.dto.RefreshTokenRequest;
import com.jwt.auth.dto.RegisterRequest;
import com.jwt.auth.dto.ResetPasswordRequest;
import com.jwt.auth.entity.RefreshToken;
import com.jwt.auth.response.ApiResponse;
import com.jwt.auth.service.AuthService;
import com.jwt.auth.service.EmailVerificationService;
import com.jwt.auth.service.PasswordResetService;
import com.jwt.auth.service.RefreshTokenService;
import com.jwt.auth.util.JwtService;

import io.swagger.v3.oas.annotations.parameters.RequestBody;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class AuthController {
    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final PasswordResetService passwordResetService;
    private final EmailVerificationService emailVerificationService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request){
        authService.register(request);
        return ResponseEntity.ok(new ApiResponse<>(true,"User registered successfully",null));
    }
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request){
        AuthResponse result = authService.login(request);
        return ResponseEntity.ok(new ApiResponse<>(true, "Login successful", result));
    }
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshTokenRequest request) {

    RefreshToken oldToken =
            refreshTokenService.verifyRefreshToken(request.getRefreshToken());

    RefreshToken newToken =
            refreshTokenService.rotateRefreshToken(oldToken);

    String newAccessToken =
            jwtService.generateToken(oldToken.getUser().getEmail());

    AuthResponse response =
            new AuthResponse(newAccessToken, newToken.getToken());

    return ResponseEntity.ok(
        new ApiResponse<>(true, "Token refreshed successfully", response)
    );
}

   @PostMapping("/logout")
   public ResponseEntity<?> logout(@Valid @RequestBody LogoutRequest request){
    authService.logout(request.getRefreshToken());
    return ResponseEntity.ok(new ApiResponse<>(true,"Logged out succesfully", null)
);
   }
   @PostMapping("/forgot-password")
   public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request){
    passwordResetService.createResetToken(request.getEmail());
    return ResponseEntity.ok(
        new ApiResponse<>(true,"Password reset token generated(check console for now)",
        null)
    );
   }

   @PostMapping("/reset-password")
   public ResponseEntity<?> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request){
                passwordResetService.resetPassword(
                    request.getToken(),
                    request.getNewPassword()
                    );
                    return ResponseEntity.ok(
                        new ApiResponse<>(true,"Password reset successful",null)
                    );
    }

    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token){
        emailVerificationService.verifyEmail(token);
        return ResponseEntity.ok(
            new ApiResponse<>(true, "Email verified succefully", null)
        );
        
    }

}
