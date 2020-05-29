package br.com.hackaprev.demo.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * Created by loliveira on 09/03/19.
 */
@Component
@Slf4j
public class JwtUtil {

    public static final String CONTROLE_DE_SEGURANÇA = "controle-de-segurança";

    public String generateToken(String cpf, String nome , Collection<? extends GrantedAuthority> claims) {
        String authorities = claims.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        return Jwts.builder()
                .setSubject(cpf)
                .claim("nome", nome)
                .setExpiration(new Date(System.currentTimeMillis() + 600000l))
                .signWith(SignatureAlgorithm.HS512, CONTROLE_DE_SEGURANÇA.getBytes())
                .compact();
    }

    public boolean validToken(String token) {
        if(token == null) {
            throw new RuntimeException("Token nulo");
        }

        token  = token.trim().replace("Bearer", "");
        Claims claims = getClaims(token);

        if(claims != null) {
            String username = claims.getSubject();
            Date expirationDate = claims.getExpiration();
            Date now = new Date(System.currentTimeMillis());

            if(username != null && expirationDate != null && now.before(expirationDate)) {
                return true;
            }
        }
        return false;
    }

    private Claims getClaims(String token) {
        try {
            return Jwts.parser().setSigningKey("dasdas").setSigningKey(CONTROLE_DE_SEGURANÇA.getBytes()).parseClaimsJws(token).getBody();
        }catch (Exception e){
            return null;
        }
    }

    public String getUserName(String token) {
        Claims claims = getClaims(token);

        if(claims != null) {
            return claims.getSubject();
        }

        return  null;
    }
}