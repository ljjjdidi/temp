package distove.auth.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import javax.validation.constraints.Email;
import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email(message = "올바른 이메일 주소를 입력해주세요.")
    @Column
    private String email;

    @Column
    private String profileImgUrl;

    @Column
    private boolean isDeleted;

    @Column
    private LocalDateTime updatedAt = LocalDateTime.now();

    @Column
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column
    private String password;

    @Column
    private String refreshToken;

    @Column
    private String nickname;

    public User(String email, String password, String nickname, String profileImgUrl) {
        this.email = email;
        this.password = password;
        this.nickname = nickname;
        this.profileImgUrl = profileImgUrl;
    }

    public void updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        this.updatedAt = LocalDateTime.now();
    }

    public void updateNickname(String nickname) {
        this.nickname = nickname;
    }

    public void updateProfileImgUrl(String profileImgUrl) {
        this.profileImgUrl = profileImgUrl;
    }
}