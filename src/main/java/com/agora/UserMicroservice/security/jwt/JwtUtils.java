package com.agora.UserMicroservice.security.jwt;

import com.agora.UserMicroservice.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

   // private String jwtSecret = "bezKoderSecretKeybezKoderSecretKeybezKoderSecretKeybezKoderSecretKeybezKoderSecretKeybezKoderSecretKeybezKoderSecretKey";
    private String jwtSecret = "3a75a0ff8d9db64d051c56d22a3cfc0355786b107b1c60d136a578b8fe456dba3a75a0ff8d9db64d051c56d22a3cfc0355786b107b1c60d136a578b8fe456dba";
    public String generateJwtToken(UserDetailsImpl userPrincipal,Long jwtExpirationTime) {
        return generateTokenFromUsername(userPrincipal.getEmail(), jwtExpirationTime);
    }

    public String generateTokenFromUsername(String username, Long jwtExpirationTime) {
        return Jwts.builder().setSubject(username).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationTime)).signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
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

    public String parseJwt(String token) {
        Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
        return claims.getSubject();
    }
    public String getEmailFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

}//Jwt