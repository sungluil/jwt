package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.domain.PrincipalDetails;
import com.cos.jwt.domain.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// login 요청해서 username, password 전송하면
// UsernamePasswordAuthenticationFilter 동작을
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // 로그인 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        System.out.println("Jwt 로그인 시도중...");

        // 1. username, password 받아서
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            //authentication객체가 session영역에 저장됨 => 로그인되었다는
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨. id = "+principalDetails.getUser().getUsername());

            //authentication객체가 session영역에 저장을 해야하고 그 방법이 return 해주면됨.
            //리턴의 이유는 권한관리를 security가 대신 해주기 때문에 편하려고 하는거임.
            //굳이 JWT토큰을 사용하면서 세션을 만들이유가 없음 근데 단지 권한처리때문에 session 넣어줍니다.

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    //attempAuthentication실행 중 인증이 정상적으로 되었으면 successfullAuthentication함수가 실행됨
    // JWT 토큰을 만들어서 request요청시 사용자에게 JWT토큰을 response해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request
            , HttpServletResponse response, FilterChain chain
            , Authentication authResult) throws IOException, ServletException {
        System.out.println("succesfulAuthentication 실행 : 인증이 완료되었다는 뜻");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //RSA방식이 아니고 Hash암호방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰") //토큰이름
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10))) //만료시간(유효시)
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
