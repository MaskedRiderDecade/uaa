package com.ihouse.uaa.config;

import com.ihouse.uaa.security.jwt.JwtFilter;
import com.ihouse.uaa.security.userdetails.UserDetailsPasswordServiceImpl;
import com.ihouse.uaa.security.userdetails.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;

import java.util.Map;

@RequiredArgsConstructor
@EnableWebSecurity(debug = true)
@Configuration
@Order(99)
@Import(SecurityProblemSupport.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final SecurityProblemSupport problemSupport;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final UserDetailsPasswordServiceImpl userDetailsPasswordServiceImpl;
    private final JwtFilter jwtFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .requestMatchers(req -> req.mvcMatchers("/api/**", "/admin/**", "/authorize/**"))
            //无状态session
            .sessionManagement(sessionManagement -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            //使用problem框架处理
            .exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(problemSupport)
                .accessDeniedHandler(problemSupport))
            .authorizeRequests(authorizeRequests -> authorizeRequests
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/api/**").hasRole("USER")
                .anyRequest().authenticated())
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            //禁用csrf，表单
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            //可以用认证头
            .httpBasic(AbstractHttpConfigurer::disable)
            ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
            .ignoring()
            .antMatchers(
                "/authorize/**",
                "/error/**",
                "/h2-console/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 配置 DaoAuthenticationProvider
        auth
            .userDetailsService(userDetailsServiceImpl) // 配置 AuthenticationManager 使用 userService
            .passwordEncoder(passwordEncoder()) // 配置 AuthenticationManager 使用 userService
            .userDetailsPasswordManager(userDetailsPasswordServiceImpl); // 配置密码自动升级服务
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 默认编码算法的 Id
        val idForEncode = "bcrypt";
        // 要支持的多种编码器
        val encoders = Map.of(
            idForEncode, new BCryptPasswordEncoder(),
            "SHA-1", new MessageDigestPasswordEncoder("SHA-1")
        );
        return new DelegatingPasswordEncoder(idForEncode, encoders);
    }
}
