package com.ihouse.uaa.domain.dto;

import com.ihouse.uaa.util.Constants;
import com.ihouse.uaa.validation.PasswordMatches;
import com.ihouse.uaa.validation.ValidEmail;
import com.ihouse.uaa.validation.ValidPassword;
import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;

@With
@Builder
@PasswordMatches
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDto implements Serializable {

    private static final long serialVersionUID = 1L;

    @NotNull
    @Size(min = 3, max = 50)
    private String username;

    @NotNull
    @Size(min = 1, max = 50)
    private String name;

    @ValidPassword
    private String password;

    @NotNull
    @Size(min = 1)
    private String matchingPassword;

    @ValidEmail
    @NotNull
    @Size(min = 1)
    private String email;

    @Pattern(regexp = Constants.PATTERN_MOBILE)
    @NotNull
    private String mobile;
}
