package com.ihouse.uaa.domain.dto;

import com.ihouse.uaa.validation.ValidPassword;
import lombok.Data;

@Data
public class PasswordDto {
    private String oldPassword;

    @ValidPassword
    private String newPassword;
}
