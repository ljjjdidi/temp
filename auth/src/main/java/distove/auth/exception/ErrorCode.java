package distove.auth.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    // 회원가입
    DUPLICATE_EMAIL(HttpStatus.CONFLICT, "A0001", "이미 존재하는 이메일입니다."),

    // 로그인
    ACCOUNT_NOT_FOUND(HttpStatus.UNAUTHORIZED, "A0002", "계정이 존재하지 않습니다."),
    INVAILD_PASSWORD(HttpStatus.UNAUTHORIZED, "A0003", "패스워드가 다릅니다."),

    //JWT
    JWT_INVALID(HttpStatus.FORBIDDEN, "A0004", "토큰이 유효하지 않습니다."),
    JWT_EXPIRED(HttpStatus.UNAUTHORIZED, "A0005", "토큰이 만료되었습니다."),
    NOT_REFRESH_TOKEN(HttpStatus.BAD_REQUEST, "A0006", "리프레시 토큰이 아닙니다."),

    // 프로필 이미지
    FILE_EXTENSION_ERROR(HttpStatus.BAD_REQUEST, "A0007", "잘못된 파일 확장자입니다."),
    FILE_UPLOAD_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "A0008", "파일 업로드에 실패했습니다.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}
