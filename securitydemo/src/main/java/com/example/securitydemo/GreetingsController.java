package com.example.securitydemo;


import com.example.securitydemo.jwt.JwtUtlis;
import com.example.securitydemo.jwt.LoginRequest;
import com.example.securitydemo.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
public class GreetingsController {

    @Autowired
     private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtlis jwtUtlis;



        @GetMapping("/hello")
        public String sayHello() {
            return "Hello";
        }

        @PreAuthorize("hasRole('USER')")
        @GetMapping("/user")
        public String userEndpoint() {
            return "Hello, User!";
        }

        @PreAuthorize("hasRole('ADMIN')")
        @GetMapping("/admin")
        public String adminEndpoint() {
            return "Hello, Admin!";
        }

        @PostMapping("/signin")
        public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
            try {
                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                loginRequest.getUsername(), loginRequest.getPassword()
                        )
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);

                Map<String, Object> response = new HashMap<>();
                response.put("message", "Login successful");
                response.put("status", true);
                response.put("username", authentication.getName());

                return ResponseEntity.ok(response);

            } catch (AuthenticationException exception) {
                Map<String, Object> error = new HashMap<>();
                error.put("message", "Bad credentials");
                error.put("status", false);
                return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
            }
        }



    /*@GetMapping("/hello")
    public String SayHello(){
        return "Hello";
    }

    @PreAuthorize("hasRole('USER')")    //is used to check auth before executing a method
    @GetMapping("/user")
    public String userEndpoint(){
        return "Hello, User!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint(){
        return "Hello, Admin!";
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;
        try{
            authentication=authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));

        }catch (AuthenticationException exception){
            Map<String,Object> map=new HashMap<>();
            map.put("message","Bad credentials");
            map.put("status",false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails=(UserDetails) authentication.getPrincipal();
        String jwtToken=jwtUtlis.generateTokenFromName(userDetails);

        List<String> roles= userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        LoginResponse response=new LoginResponse(userDetails.getUsername(),roles,jwtToken);
        return ResponseEntity.ok(response);
    }
*/

}
