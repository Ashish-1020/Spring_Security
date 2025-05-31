package com.example.securitydemo.jwt;

import java.util.List;

public class LoginResponse {

    private String jwtToken;
    private String userName;
    private List<String> roles;

    public LoginResponse( String userName,List<String> roles, String jwtToken) {
        this.roles = roles;
        this.userName = userName;
        this.jwtToken = jwtToken;
    }
}
