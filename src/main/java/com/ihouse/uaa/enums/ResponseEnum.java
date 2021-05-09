package com.ihouse.uaa.enums;

import lombok.Getter;

@Getter
public enum ResponseEnum {

    ERROR(-1, "服务端错误"),

    SUCCESS(0, "成功"),

    PARAM_ERROR(3, "参数错误"),

    NEED_LOGIN(10, "用户未登录, 请先登录")

    ;

    Integer code;

    String desc;

    ResponseEnum(Integer code, String desc) {
        this.code = code;
        this.desc = desc;
    }
}
