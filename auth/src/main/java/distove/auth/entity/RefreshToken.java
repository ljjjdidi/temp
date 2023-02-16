package distove.auth.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@RedisHash(value = "refreshToken", timeToLive = 60)
public class RefreshToken {

    @Id
    private Long userId;
    private String refreshToken;

    public RefreshToken(final String refreshToken, final Long userId) {
        this.refreshToken = refreshToken;
        this.userId = userId;

    }

    public Long getUserId() {
        return userId;
    }
    public String getRefreshToken() {
        return refreshToken;
    }
}
