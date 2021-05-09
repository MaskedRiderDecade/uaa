package com.ihouse.uaa.util;

import com.ihouse.uaa.config.AppProperties;
import com.ihouse.uaa.domain.Role;
import com.ihouse.uaa.domain.User;
import io.jsonwebtoken.Jwts;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;


@ExtendWith(SpringExtension.class)
public class JwtUtilUnitTests {

    private JwtUtil jwtUtil;

    @BeforeEach
    public void setUp(){
        jwtUtil=new JwtUtil(new AppProperties());
    }


    @Test
    public void givenUserDetails(){
        val username="user";
        val authorities= Set.of(
            Role.builder()
            .authority("ROLE_USER")
            .build(),
            Role.builder()
            .authority("ROLE_ADMIN")
            .build());
        val user= User.builder()
            .username(username)
            .authorities(authorities)
            .build();
        //创建
        val token=jwtUtil.createAccessToken(user);
        //解析
        val parseClaims= Jwts.parserBuilder().
            setSigningKey(JwtUtil.key).build()
            .parseClaimsJws(token)
            .getBody();
        assertEquals(username,parseClaims.getSubject());
    }
}
