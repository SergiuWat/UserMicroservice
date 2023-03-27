package com.agora.UserMicroservice.controller;

import com.agora.UserMicroservice.entity.ERole;
import com.agora.UserMicroservice.entity.Role;
import com.agora.UserMicroservice.entity.User;
import com.agora.UserMicroservice.payload.request.LoginRequest;
import com.agora.UserMicroservice.payload.request.SignupRequest;
import com.agora.UserMicroservice.payload.response.JwtResponse;
import com.agora.UserMicroservice.payload.response.MessageResponse;
import com.agora.UserMicroservice.repository.RoleRepository;
import com.agora.UserMicroservice.repository.UserRepository;
import com.agora.UserMicroservice.security.WebSecurityConfig;
import com.agora.UserMicroservice.security.jwt.JwtUtils;
import com.agora.UserMicroservice.security.services.RefreshTokenService;
import com.agora.UserMicroservice.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/")
public class UserController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String accessToken = jwtUtils.generateJwtToken(userDetails, 900000L);

        String refreshToken = jwtUtils.generateJwtToken(userDetails, 86400000L);

        User user =userRepository.findByEmail(userDetails.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " +userDetails.getEmail()));

        refreshTokenService.createRefreshToken(user, refreshToken);

        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList());



        return ResponseEntity.ok(new JwtResponse(accessToken, refreshToken, userDetails.getId(),
                userDetails.getUsername(), userDetails.getEmail(), roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        roles.add(userRole);

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Long userId = userDetails.getId();
        refreshTokenService.deleteByUserId(userId);
        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }



    @DeleteMapping("/users/{email}")
    public ResponseEntity<String> deleteUserByEmail(@PathVariable("email") String email, @RequestHeader(value="Authorization") String token) {
        token = token.split(" ")[1].trim();

        if (jwtUtils.validateJwtToken(token)) {

            User user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User Not Found with email: " + email));
            refreshTokenService.deleteByUserId(user.getId());
            userRepository.delete(user);

            return ResponseEntity.ok("User with email: " + email + " has been deleted successfully");
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

    }//deleteUserByEmail

    @PutMapping("/users/password")

    public ResponseEntity<?> updateUserPassword(@Valid @RequestBody Map<String, String> passwordRequest,
                                                @RequestHeader(value="Authorization") String token) {

        token = token.split(" ")[1].trim();

        if (jwtUtils.validateJwtToken(token)) {

            UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            User user = userRepository.findByEmail(userDetails.getEmail()).orElseThrow(() -> new UsernameNotFoundException
                    ("User Not Found with email: " + userDetails.getEmail()));

            String oldPassword = passwordRequest.get("CurrentPassword");
            String newPassword = passwordRequest.get("newPassword");

            if (oldPassword == null || newPassword == null) {
                return ResponseEntity.badRequest().body(new MessageResponse("Error: Old and new passwords are required! :P"));
            }

            if (!encoder.matches(oldPassword, user.getPassword())) {
                return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid old password!!!"));
            }

            user.setPassword(encoder.encode(newPassword));
            userRepository.save(user);

            return ResponseEntity.ok(new MessageResponse("Password updated successfully! :3"));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Error: Unauthorized!"));
        }
    }//updatePass

}//UserController
