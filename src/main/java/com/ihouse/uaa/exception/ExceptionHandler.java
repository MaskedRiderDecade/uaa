package com.ihouse.uaa.exception;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.zalando.problem.spring.web.advice.ProblemHandling;

@ControllerAdvice
public class ExceptionHandler implements ProblemHandling {
    //是否包含详细debug信息
    @Override
    public boolean isCausalChainsEnabled() {
        return true;
    }
}
