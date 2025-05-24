package com.example.securitydemo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration   // this annotation tell that this file provides the configuration to application context
@EnableWebSecurity // this tell spring boot to enable web security features and give us the liberty to customize the security configuration
@EnableMethodSecurity // to allopw role based authorization
public class SecurityConf {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated()); // any request recieved is by default authenticated
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // to have stateless session no cookies while login
        // http.formLogin(withDefaults());
        http.httpBasic(withDefaults()); //basic auth with default settings
        return http.build();
    }

    @Bean
    public UserDetailsService userDeatailService(){  // this is the inmemory authentication using the default UserDetails object to create users
        UserDetails user1= User.withUsername("user1")
                .password("{noop}password1")
                .roles("USER")
                .build();

        UserDetails admin=User.withUsername("admin")
                .password("{noop}passWord")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager( user1, admin);
    }
}
