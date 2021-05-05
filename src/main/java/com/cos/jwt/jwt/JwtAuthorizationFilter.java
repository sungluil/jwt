package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.domain.PrincipalDetails;
import com.cos.jwt.domain.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//시큐리티가 filter를 가지고있는데 그 필터중에 이
//BasicAuthenticationFilter라는 것이 있는데
//권한이나 인증이 필요한 특정 주소를 요청했을때 위 필터를 무조건 타게되어있음
//만약에 권한이 인증이 필요한 주소가 아니라면 필터를 안탐
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
                                  UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    //인증이나 권한이 필요한 주소요청이 있을때 해당 필터를 타게됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
//        super.doFilterInternal(request, response, chain);//삭제
        System.out.println("인증이나 권한이 필요한 주소 요청이 ");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = "+jwtHeader);

        //Header가 있는지 확인
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        //JWT토큰을 검정을 해서 정상적인 사용자 인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ","");

        String username = JWT.require(Algorithm.HMAC512("cos"))
                .build().verify(jwtToken).getClaim("username").asString();

        //서명이 정상적으로 된 경우
        if(username != null) {
            User user = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(user);

            //Jwt줌 토큰 서명을 통해서 서명이 정상적이면 Authentication객체를 만들어
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null
                            , principalDetails.getAuthorities());

            //강제로 시큐리티의 세션에 접근하여 Authentication객체 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
    }
}
