package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰을 만들어줘야하는데 id pw가 정상적으로 들어와서 로그인이 완료되면 토큰생성
        // 요청할때마다 header에 Authorization에 value값으로 토큰을 가지고 오면
        // 그때 토큰이 넘어오면 그 토큰이 내가만든 토큰이 맞는지 검증만 하면(RSA, HS256)
        chain.doFilter(req, res);
    }
}
