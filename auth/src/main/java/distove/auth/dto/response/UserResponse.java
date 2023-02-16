package distove.auth.dto.response;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class UserResponse {

    private Long id;
    private String nickname;
    private String profileImgUrl;

    public static UserResponse of(Long id, String nickname, String profileImgUrl) {
        return UserResponse.builder()
                .id(id)
                .nickname(nickname)
                .profileImgUrl(profileImgUrl)
                .build();
    }
}
