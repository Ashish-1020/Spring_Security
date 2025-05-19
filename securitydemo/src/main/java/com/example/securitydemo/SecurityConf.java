package com.example.securitydemo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration   // this annotation tell that this file provides the configuration to application context
@EnableWebSecurity // this tell spring boot to enable web security features and give us the liberty to customize the security configuration
public class SecurityConf {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated()); // any request recieved is by default authenticated
       // http.formLogin(withDefaults());
        http.httpBasic(withDefaults()); //basic auth with default settings
        return http.build();
    }
}
