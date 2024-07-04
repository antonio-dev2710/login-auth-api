package com.example.login_auth_api.controllers;

import com.example.login_auth_api.domain.User;
import com.example.login_auth_api.dto.LoginRequestDTO;
import com.example.login_auth_api.dto.RegisterRequestDTO;
import com.example.login_auth_api.dto.ResponseDTO;
import com.example.login_auth_api.infra.security.TokenService;
import com.example.login_auth_api.repositoreis.UserRepository;
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
public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body) {

        User user = userRepository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User not found "));
        if (passwordEncoder.matches(user.getPassword(), body.password())) {
            //vai gerar um novo token
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));
        }

        return ResponseEntity.badRequest().build();

    }


    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body) {
        //criar um novo usuário
        Optional<User> user = userRepository.findByEmail(body.email());
        if (user.isEmpty()) {
            User userNew = new User();
            userNew.setPassword(passwordEncoder.encode(body.password()));
            userNew.setEmail(body.email());
            userNew.setName(body.name());

            this.userRepository.save(userNew);

            //vai gerar um novo token
            String token = this.tokenService.generateToken(userNew);
            return ResponseEntity.ok(new ResponseDTO(userNew.getName(), token));

        }


        return ResponseEntity.badRequest().build();

    }

}
