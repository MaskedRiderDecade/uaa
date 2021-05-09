package com.ihouse.uaa.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ihouse.uaa.config.AppProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static java.util.stream.Collectors.toList;

@RequiredArgsConstructor
@Component
@Slf4j
public class JwtUtil {
    //访问令牌签名算法
    public static final Key key=  Keys.hmacShaKeyFor(Decoders.BASE64.decode("cuAihCz53DZGundam001sGcZJ2Ai6AUnicornuphtJMsk7iQ="));
    //刷新令牌签名算法
    public static final Key refreshKey= Keys.hmacShaKeyFor(Decoders.BASE64.decode("cuAihCz53DZGundam001sGcZJ2Ai6AUnicornuphtJMsk7iQ="));

    private ObjectMapper objectMapper=new ObjectMapper();

    private final AppProperties appProperties;
    public String createJwtToken(UserDetails userDetails,long timeToExpire,Key key){
        val now=System.currentTimeMillis();
        return Jwts.builder()
            .setId("ihouse")
            .claim("authorities",userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toList()))
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(now))
            .setExpiration(new Date(now+timeToExpire))
            .signWith(key)
            .compact();
    }
    public String createAccessToken(UserDetails userDetails){
        return createJwtToken(userDetails,appProperties.getJwt().getAccessTokenExpireTime(),key);
    }

    public String createRefreshToken(UserDetails userDetails){
        return createJwtToken(userDetails,appProperties.getJwt().getRefreshTokenExpireTime(),refreshKey);
    }

    public boolean validateAccessToken(String token){
        return validateToken(token,key,true);
    }

    public boolean validateWithoutExpiration(String token){
        return validateToken(token,key,false);
    }

    public boolean validateAdminAccessToken(String token){
        return validateAdminToken(token,key,true);
    }

    public boolean validateAdminWithoutExpiration(String token){
        return validateAdminToken(token,key,false);
    }

    public boolean validateRefreshToken(String token){
        return validateToken(token,refreshKey,true);
    }

    public boolean validateToken(String token,Key key,boolean isExpiredInvalid){
        try{
//            Jwts.parserBuilder().setSigningKey(key).build().parse(token);
            Claims body= (Claims) Jwts.parserBuilder().setSigningKey(key).build().parse(token).getBody();
            List<String> authorities= (List<String>) body.get("authorities");
            for(String authority:authorities){
                log.info(authority+"\n");
            }
            return true;
        }catch(ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e){
            if(e instanceof ExpiredJwtException){
                return !isExpiredInvalid;
            }
            return false;
        }

    }

    public boolean validateAdminToken(String token,Key key,boolean isExpiredInvalid){
        try{
            Jwt jwt=Jwts.parserBuilder().setSigningKey(key).build().parse(token);
            Claims body= (Claims) jwt.getBody();
            List<String> authorities= (List<String>) body.get("authorities");
            if(authorities!=null&&authorities.contains("ROLE_ADMIN")){
                return true;
            }
            return  false;
        }catch(ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e){
            if(e instanceof ExpiredJwtException){
                return !isExpiredInvalid;
            }
            return false;
        }

    }

    private Optional<Claims> parseClaims(String token,Key key){
        try{
          val claims=Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
          return Optional.of(claims);
        }
        catch(Exception e){
            return Optional.empty();

        }
    }

    public String buildAccessTokenWithRefreshToken(String token){
        return parseClaims(token,refreshKey)
            .map(claims -> Jwts.builder()
            .setClaims(claims)
            .setExpiration(new Date(System.currentTimeMillis()+appProperties.getJwt().getAccessTokenExpireTime()))
            .setIssuedAt(new Date())
            .signWith(key)
            .compact()
            )
            .orElseThrow(()->new AccessDeniedException("访问被拒绝"));

    }
}
