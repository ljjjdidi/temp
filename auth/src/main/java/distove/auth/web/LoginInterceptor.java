package distove.auth.web;

import distove.auth.exception.DistoveException;
import distove.auth.service.JwtTokenProvider;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.security.sasl.AuthenticationException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static distove.auth.exception.ErrorCode.JWT_EXPIRED;
import static distove.auth.exception.ErrorCode.JWT_INVALID;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginInterceptor implements HandlerInterceptor {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException, JwtException {
        String token = request.getHeader("token");
        if (token == null) {
            throw new AuthenticationException("JWT is null");
        }
        try {
            jwtTokenProvider.validToken(token);
            return true;
        } catch (UnsupportedJwtException e) {
            throw new DistoveException(JWT_INVALID);
        } catch (ExpiredJwtException e) {
            throw new DistoveException(JWT_EXPIRED);
        }

    }
}
