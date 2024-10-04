package com.app.util;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.awt.*;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    @Value("${security.jwt.key.private}")
    private String privateKey;

    @Value("${security.jwt.user.generator}")
    private String userGenerator;

    // Metodo para crear el token
    public String createToken(Authentication authentication) {
        Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

        String username = authentication.getPrincipal().toString();
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        String jwtToken = JWT.create()
                .withIssuer(this.userGenerator) // Usuario que se utiliza para encryptar
                .withSubject(username) // Usuario al que se le va a generar el token
                .withClaim("authorities", authorities) // Los permisos que va a terner ese usuario
                .withIssuedAt(new Date()) // Fecha en la que se genera el token
                .withExpiresAt(new Date(System.currentTimeMillis() + 1800000)) // Tiempo que va a durar el vigencia ese token
                .withJWTId(UUID.randomUUID().toString()) // Identificador de ese token generado
                .withNotBefore(new Date(System.currentTimeMillis())) // Momento desdes que el token entra en vigencia
                .sign(algorithm); // Tipo de algoritmo de encryptacion

        return jwtToken;
    }

    // Metodo para validar el token
    public DecodedJWT validateToken(String token) {
        try{
            Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(this.userGenerator)
                    .build();

            DecodedJWT decodedJWT = verifier.verify(token);
            return decodedJWT;
        }catch (JWTVerificationException exception){
            throw new JWTVerificationException("Token invalid, not Authorixed");
        }
    }

    // Metodo para extraer el usuario que viene el token
    public String extractUsername(DecodedJWT decodedJWT){
        return decodedJWT.getSubject().toString();
    }

    // Metodo para extraer un Clain especifico
    public Claim getSpecificClaim (DecodedJWT decodedJWT, String claimName){
        return decodedJWT.getClaim(claimName);
    }

    // Metodo para traer todos los Claim
    public Map<String, Claim> returnAllClaims(DecodedJWT decodedJWT){
        return decodedJWT.getClaims();
    }
}
