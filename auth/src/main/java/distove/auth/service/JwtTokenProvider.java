package distove.auth.service;

import distove.auth.entity.RefreshToken;
import distove.auth.exception.DistoveException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static distove.auth.exception.ErrorCode.JWT_EXPIRED;
import static distove.auth.exception.ErrorCode.JWT_INVALID;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final Key key;

    @Autowired
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createToken(Long userId, String type) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "HS256");
        Claims claims = Jwts.claims().setSubject("userId");
        claims.put("userId", userId);

        Date now = new Date();

        if (type.equals("AT")) {
            headers.put("type", "AT");
            return Jwts.builder()
                    .setHeader(headers)
                    .setClaims(claims)
                    .setIssuedAt(now)
                    .setExpiration(new Date(now.getTime() + Duration.ofMinutes(43200).toMillis()))
                    .signWith(key, SignatureAlgorithm.HS256)
                    .compact();
        } else {
            headers.put("type", "RT");
            return Jwts.builder()
                    .setHeader(headers)
                    .setClaims(claims)
                    .setIssuedAt(now)
                    .setExpiration(new Date(now.getTime() + Duration.ofDays(30).toMillis()))
                    .signWith(key, SignatureAlgorithm.HS256)
                    .compact();
        }
    }


    public ResponseCookie createTokenCookie(String refreshToken) {
        return ResponseCookie.from("refreshToken", refreshToken)
                .maxAge(60 * 60 * 24 * 30)
                .path("/")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .domain("distove.onstove.com")
                .build();
    }

    public RefreshToken refreshTokenToEntity(String token, Long userId) {
        return new RefreshToken(token, userId);
    }

    public boolean validToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (UnsupportedJwtException e) {
            throw new DistoveException(JWT_INVALID);
        } catch (ExpiredJwtException e) {
            throw new DistoveException(JWT_EXPIRED);
        }
    }

    public String getTypeOfToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token).getHeader().get("type").toString();

        } catch (UnsupportedJwtException e) {
            throw new DistoveException(JWT_INVALID);
        } catch (ExpiredJwtException e) {
            throw new DistoveException(JWT_EXPIRED);
        }
    }

    public Long getUserId(String token) throws DistoveException {
        try {
            return Long.valueOf(String.valueOf(Jwts
                    .parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .get("userId")));
        } catch (ExpiredJwtException e) {
            throw new DistoveException(JWT_EXPIRED);
        } catch (Exception e) {
            throw new DistoveException(JWT_INVALID);
        }
    }
}