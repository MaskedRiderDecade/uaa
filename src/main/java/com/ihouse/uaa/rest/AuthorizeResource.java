package com.ihouse.uaa.rest;

import com.ihouse.uaa.domain.Auth;
import com.ihouse.uaa.domain.Role;
import com.ihouse.uaa.domain.User;
import com.ihouse.uaa.domain.dto.LoginDto;
import com.ihouse.uaa.exception.*;

import com.ihouse.uaa.service.UserService;
import com.ihouse.uaa.util.JwtUtil;
import com.ihouse.uaa.util.SecurityUtil;
import com.ihouse.uaa.domain.dto.UserDto;
import com.ihouse.uaa.vo.ResponseVo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.context.MessageSource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@RestController
@RequestMapping("/authorize")
@Slf4j
public class AuthorizeResource {

    private final UserService userService;

    private final MessageSource messageSource;

    private final JwtUtil jwtUtil;


    @GetMapping(value="greeting")
    public String sayHello() {
        return "hello world";
    }

    @Transactional
    @PostMapping("/register")
    public void register(@Valid @RequestBody UserDto userDto) {
        //查询数据库，确保username，email，mobile唯一
        //userDto转换成user，给一个默认角色再保存
        if(userService.isUsernameExisted(userDto.getUsername())){
             throw new DuplicateProblem("用户名重复");
        }
        if(userService.isEmailExisted(userDto.getEmail())){
            throw new DuplicateProblem("邮箱重复");
        }
        if(userService.isMobileExisted(userDto.getMobile())){
            throw new DuplicateProblem("手机号码重复");
        }

        val user= User.builder()
            .username(userDto.getUsername())
            .name(userDto.getName())
            .email(userDto.getEmail())
            .mobile(userDto.getMobile())
            .password(userDto.getPassword())
            .build();



        userService.register(user);
    }

    @PostMapping("/token")
    public ResponseVo login(@Valid @RequestBody LoginDto loginDTO) {
        return userService.findOptionalByUsernameAndPassword(loginDTO.getUsername(),loginDTO.getPassword())
            .map(user -> {
                userService.upgradePasswordEncodingIfNeeded(user,loginDTO.getPassword());
                if(!user.isEnabled()){
                    throw new UserNotEnabledProblem();
                }
                if(!user.isAccountNonExpired()){
                    throw new UserAccountExpiredProblem();
                }
                if(!user.isAccountNonLocked()){
                    throw new UserAccountLockedProblem();
                }
                if(!user.isCredentialsNonExpired()){
                    throw new BadCredentialProblem();
                }
                return ResponseVo.success(userService.login(user));
            })
            .orElseThrow(()->new BadCredentialsException("用户名或密码错误"));
    }

    @PostMapping("/admin/token")
    public ResponseVo adminLogin(@Valid @RequestBody LoginDto loginDTO) {
        return userService.findOptionalByUsernameAndPassword(loginDTO.getUsername(),loginDTO.getPassword())
            .map(user -> {
                userService.upgradePasswordEncodingIfNeeded(user,loginDTO.getPassword());
                if(!user.isEnabled()){
                    throw new UserNotEnabledProblem();
                }
                if(!user.isAccountNonExpired()){
                    throw new UserAccountExpiredProblem();
                }
                if(!user.isAccountNonLocked()){
                    throw new UserAccountLockedProblem();
                }
                if(!user.isCredentialsNonExpired()){
                    throw new BadCredentialProblem();
                }
                boolean isAdmin=false;
                for(Role role:user.getAuthorities()){
                    if(role.getAuthority().equals("ROLE_ADMIN")){
                        log.info("ROLE_ADMIN");
                        isAdmin=true;
                        break;
                    }
                }
                if(!isAdmin){
                    throw new NotAdminProblem();
                }
                return ResponseVo.success(userService.login(user));
            })
            .orElseThrow(()->new BadCredentialsException("用户名或密码错误"));
    }


    @PostMapping("/token/refresh")
    public ResponseVo refreshToken(@RequestHeader(name = "Authorization") String authorization, @RequestParam String refreshToken) {
        val PREFIX = "Bearer ";
        val accessToken = authorization.replace(PREFIX, "");
        if (jwtUtil.validateRefreshToken(refreshToken) && jwtUtil.validateWithoutExpiration(accessToken)) {
            return ResponseVo.success(new Auth(jwtUtil.buildAccessTokenWithRefreshToken(refreshToken), refreshToken));
        }
        throw new AccessDeniedException("Bad Credentials");
    }

    @PostMapping("admin/token/refresh")
    public ResponseVo refreshAdminToken(@RequestHeader(name = "Authorization") String authorization, @RequestParam String refreshToken){
        val PREFIX = "Bearer ";
        val accessToken = authorization.replace(PREFIX, "");
        if(jwtUtil.validateRefreshToken(refreshToken)&&jwtUtil.validateAdminWithoutExpiration(accessToken)){
            return ResponseVo.success(new Auth(jwtUtil.buildAccessTokenWithRefreshToken(refreshToken), refreshToken));
        }
        throw new AccessDeniedException("Bad Credentials");
    }

    @GetMapping("/problem")
    public void raiseProblem() {
        throw new AccessDeniedException("You do not have the privilege");
    }

    @GetMapping("/anonymous")
    public String getAnonymous() {
        return SecurityUtil.getCurrentLogin();
    }
}
