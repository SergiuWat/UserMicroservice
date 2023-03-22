package com.agora.UserMicroservice.controller;

import com.agora.UserMicroservice.payload.request.TokenRefreshRequest;
import com.agora.UserMicroservice.payload.response.MessageResponse;
import com.agora.UserMicroservice.security.jwt.JwtUtils;
import com.agora.UserMicroservice.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/")
public class RefreshTokenController {
    @Autowired
    JwtUtils jwtUtils;
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();
        if(jwtUtils.validateJwtToken(requestRefreshToken)){
            UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String newAccessToken = jwtUtils.generateJwtToken(userDetails, 7200000L);
            return ResponseEntity.ok(newAccessToken);
        }

        return ResponseEntity.badRequest().body(new MessageResponse("Error: Could not validate the token!"));
    }

    @PostMapping("/verifytoken")
    public HttpStatusCode verifyToken(@Valid @RequestBody TokenRefreshRequest request){
        String requestVerifyToken = request.getRefreshToken();
        if(jwtUtils.validateJwtToken(requestVerifyToken)){
            return ResponseEntity.ok("200").getStatusCode();
        }
        return ResponseEntity.badRequest().build().getStatusCode();
    }

}
