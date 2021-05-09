package com.ihouse.uaa.exception;

import com.ihouse.uaa.util.Constants;
import org.zalando.problem.AbstractThrowableProblem;
import org.zalando.problem.Status;

import java.net.URI;

public class DuplicateProblem extends AbstractThrowableProblem {
    private static final URI type=URI.create(Constants.PROBLEM_BASE_URI+"/duplicate");
    public DuplicateProblem(String message){
        super(type,"发现重复数据", Status.CONFLICT,message);
    }
}
