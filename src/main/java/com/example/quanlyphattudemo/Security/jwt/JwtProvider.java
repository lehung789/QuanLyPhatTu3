package com.example.quanlyphattudemo.Security.jwt;


import com.example.quanlyphattudemo.Security.userPrincipal.UserPrincipal;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
// chua pthuc thao tac jwt lay valudate dl token

@Component // autoroud
public class JwtProvider {
    public static Logger logger = LoggerFactory.getLogger(JwtProvider.class);
    private static final String SECRET_KEY = "DrCbV4rwggp8LuKNEvRIoEoUq5prmhoQO2EFGV6iKC8GuBN2UJsyu5RTRI6YiJbc";
    private static final long TOKEN_EXPIRED = 86400000;
    // login  doi tg Authentication hứng thông tin user pasw thực hiện truyên cho secutrity
    public String generateToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime()+ TOKEN_EXPIRED))
                .signWith(SignatureAlgorithm.HS512,SECRET_KEY)
                .compact();
    }
    public boolean validateToken( String token){
        try {
            // par token. phas jwt = key . dulieu payload
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token);
            return true;
            // token het han
        } catch (ExpiredJwtException e){
            logger.error("Failed -> Expired ToKen Message {}", e.getMessage());
        }
        // token k thuoc hethong
        catch (UnsupportedJwtException e){
            logger.error("Failed -> Unsupported ToKen Message {}", e.getMessage());
        }
        // k dung format
        catch (MalformedJwtException e){
            logger.error("Failed -> Invalid Format ToKen Message {}", e.getMessage());
        }
        // sai Signature(chu ki)
        catch (SignatureException e){
            logger.error("Failed -> Invalid Signature ToKen Message {}", e.getMessage());
        }
        // null
        catch (IllegalArgumentException e){
            logger.error("Failed -> Claims Empty ToKen Message {}", e.getMessage());
        }
        return false;
    }
    // lay tt user
    // par token pha khoa laypayload bo ngoac lay body - lay usrname
    public String getUserNameFromToken(String token){
        return Jwts.parser().setSigningKey(SECRET_KEY)
                .parseClaimsJws(token).getBody().getSubject();
    }

}
