package com.example.login_auth_api.application.commands.auth;

import com.example.login_auth_api.application.dto.auth.login.LoginRequestDTO;
import com.example.login_auth_api.application.dto.auth.login.LoginResponseDTO;
import com.example.login_auth_api.application.dto.auth.register.RegisterRequestDTO;
import com.example.login_auth_api.application.dto.auth.register.RegisterResponseDTO;
import com.example.login_auth_api.domain.user.User;
import com.example.login_auth_api.infra.security.TokenService;
import com.example.login_auth_api.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthCommandController {

    private final UserRepository repository;
    private  final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO body){
    User user = this.repository.findByEmail(body.email()).orElseThrow(()-> new RuntimeException("User not found"));
    if(passwordEncoder.matches(user.getPassword(), body.password())){
        String token = this.tokenService.generateToken(user);
        return ResponseEntity.ok(new LoginResponseDTO(user.getName(), token));
    }
    return  ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponseDTO> register(@RequestBody RegisterRequestDTO body){
        Optional<User> user = this.repository.findByEmail(body.email());

        if(user.isEmpty()){
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            this.repository.save(newUser);

            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new RegisterResponseDTO(newUser.getName(), token));
        }
        return  ResponseEntity.badRequest().build();
    }
}
