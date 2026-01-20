package com.example.demo.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
//    Getting JWT from header
    @Value("${spring.app.jwtExpiration}")
    private int jwtExpiration;
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    private final Logger logger= LoggerFactory.getLogger(JwtUtils.class);
    public String getJWTFromHeader(HttpServletRequest request){//returning token in string
        String bearerToken=request.getHeader("Authorization");
        logger.debug("Authoeization Header: {}",bearerToken);
        if(bearerToken!=null && bearerToken.startsWith("Bearer")){
            return bearerToken.substring(7);
        }
        return null;
    }
//    Generating TOken from username
    public String generateTOkenFromUsername(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime()+jwtExpiration))
                .signWith(key())
                .compact();
    }
//    Getting username from JWT token
    public String getUserNameFromJWTToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }
//    Generate signing key
    public Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecret));
    }
//    Validate JWT token
    public boolean validateJwtToken(String authToken){
        try{
            System.out.println("Validate");
            Jwts.parser()
                    .verifyWith((SecretKey)key())
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        }
        catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());

        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());

        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());

        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

}

