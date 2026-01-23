package com.example.demo;

import com.example.demo.jwt.JwtUtils;
import com.example.demo.jwt.LoginRequest;
import com.example.demo.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@EnableMethodSecurity
public class Controller {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;
    @GetMapping("/hello")
    public String hello(){
        return "Hello";
    }
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint(){
        return "Hello, USER";
    }
    @PreAuthorize(("hasRole('ADMIN')"))
    @GetMapping("/admin")
    public String adminendpoint(){
        return "Hello";
    }
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
        } catch (AuthenticationException e) {
            Map<String,Object> map =  new HashMap<>();
            map.put("message","Bad credentials");
            map.put("status",false);
            return  new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
//        authentication.getPrincipal() returns “WHO is the currently logged-in user”.
        UserDetails userDetails=(UserDetails) authentication.getPrincipal();
        String jwtToken= jwtUtils.generateTOkenFromUsername(userDetails);
        List<String> roles= userDetails.getAuthorities().stream()
                .map(item->item.getAuthority())
                .toList();
        LoginResponse loginResponse= new LoginResponse(jwtToken,userDetails.getUsername(),roles);
        return new ResponseEntity<>(loginResponse,HttpStatus.OK);
    }
}
