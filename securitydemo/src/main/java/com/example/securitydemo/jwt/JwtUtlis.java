package com.example.securitydemo.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.catalina.users.SparseUserDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;
import java.util.Date;



@Component
public class JwtUtlis {
    private static  final Logger logger= LoggerFactory.getLogger(JwtUtlis.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public  String getJwtFromHeader(HttpServletRequest request){
        String bearerToken=request.getHeader("Authorization");
        logger.debug("Authorization Header: {}",bearerToken);
        if(bearerToken!=null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }

    public String generateTokenFromName(UserDetails userDetails){
        String username=userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime()+jwtExpirationMs))
                .signWith(key())
                .compact();
    }


    private Key key(){
       return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret)) ;
    }

    public String getUserNameFromJwtToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey)key()).build()
                .parseSignedClaims(token)
                .getPayload().getSubject();
    }


    public  boolean valiodateJwtToken(String authToken){
        try{
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;

        }catch (MalformedJwtException e){
            logger.error("Invalid JWT token:{}",e.getMessage());
        }
        catch (ExpiredJwtException e){
            logger.error("JWT token is expired :{}",e.getMessage());
        }
        catch (UnsupportedJwtException e){
            logger.error("JWT token is unsupported:{}",e.getMessage());
        }catch (IllegalArgumentException e){
            logger.error("JWT claims string is empty :{}",e.getMessage());
        }
        return false;
    }


    




}
