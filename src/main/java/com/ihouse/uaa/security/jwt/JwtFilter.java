package com.ihouse.uaa.security.jwt;

import com.ihouse.uaa.config.AppProperties;
import com.ihouse.uaa.util.CollectionUtil;
import com.ihouse.uaa.util.JwtUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.channels.IllegalChannelGroupException;
import java.util.Optional;

import static java.util.stream.Collectors.toList;

@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final AppProperties appProperties;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(ckeckJwtToken(request)){
            validateToken(request)
                .filter(claims -> claims.get("authorities")!=null)
                //authorities有值就保存到SecurityContextHolder，没有值就清空
                .ifPresentOrElse(
                    this::setUpSpringAuthentication,
                    SecurityContextHolder::clearContext);
        }
        filterChain.doFilter(request,response);
    }

    private void setUpSpringAuthentication(Claims claims) {
        val rawList= CollectionUtil.convertObjectToList(claims.get("authorities"));
        val authorities=rawList.stream()
            .map(String::valueOf)
            .map(SimpleGrantedAuthority::new)
            .collect(toList());
        val authentication=new UsernamePasswordAuthenticationToken(claims.getSubject(),null,authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private Optional<Claims> validateToken(HttpServletRequest request){
        String jwtToken=request.getHeader(appProperties.getJwt().getHeader()).replace(appProperties.getJwt().getPrefix(),"");
        try{
            return Optional.of(Jwts.parserBuilder().setSigningKey(JwtUtil.key).build().parseClaimsJws(jwtToken).getBody());
        }catch (ExpiredJwtException| SignatureException| MalformedJwtException| UnsupportedJwtException| IllegalArgumentException e){
            return Optional.empty();
        }
    }

    //检查jwt是否在http头中
    private boolean ckeckJwtToken(HttpServletRequest request) {
        String authenticationHeader=request.getHeader(appProperties.getJwt().getHeader());
        return authenticationHeader!=null&&authenticationHeader.startsWith(appProperties.getJwt().getPrefix());
    }
}
