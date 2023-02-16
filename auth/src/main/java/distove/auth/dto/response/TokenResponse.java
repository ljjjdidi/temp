package distove.auth.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class TokenResponse {
    private String accessToken;
    private String cookie;

    public static TokenResponse of(String accessToken, String cookie) {
        return TokenResponse.builder()
                .accessToken(accessToken)
                .cookie(cookie)
                .build();
    }
}

