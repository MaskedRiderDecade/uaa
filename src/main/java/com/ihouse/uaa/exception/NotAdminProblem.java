package com.ihouse.uaa.exception;

import com.ihouse.uaa.util.Constants;
import org.zalando.problem.AbstractThrowableProblem;
import org.zalando.problem.Status;

import java.net.URI;

public class NotAdminProblem extends AbstractThrowableProblem {
    private static final URI type=URI.create(Constants.PROBLEM_BASE_URI+"/notAdmin");
    public NotAdminProblem(){
        super(type,"未授权访问", Status.UNAUTHORIZED,"不是管理员，无权访问");
    }
}
