package com.ihouse.uaa.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Validated
@Configuration
@ConfigurationProperties(prefix = "ihouse")
public class AppProperties {

    @Getter
    @Setter
    private Jwt jwt=new Jwt();

    @Getter
    @Setter
    public static class Jwt{
        private String header="Authorization";
        private String prefix="Bearer ";
        //访问令牌过期时间
        private Long accessTokenExpireTime=5184000L;
        //刷新令牌过期时间
        private Long refreshTokenExpireTime=30*24*60*3600L;
    }
}
