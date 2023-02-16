package distove.auth.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class DistoveException extends RuntimeException {

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;

    public DistoveException(ErrorCode errorCode) {
        this.httpStatus = errorCode.getHttpStatus();
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
    }

}

