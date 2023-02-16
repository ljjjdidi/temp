package distove.auth.dto.response;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class LogoutResponse {
    private String email;

    public static LogoutResponse of(String email) {
        return LogoutResponse.builder()
                .email(email)
                .build();
    }
}