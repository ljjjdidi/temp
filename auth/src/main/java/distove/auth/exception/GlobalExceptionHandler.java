package distove.auth.exception;

import distove.auth.dto.response.ResultResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> defaultExceptionHandler(Exception e) {
        log.error("[" + e.getClass().getSimpleName() + "] " + e.getMessage());
        return ResultResponse.fail(INTERNAL_SERVER_ERROR, "X9999", e.getMessage());
    }

    @ExceptionHandler(DistoveException.class)
    public ResponseEntity<Object> distoveExceptionHandler(DistoveException e) {
        log.error("[" + e.getClass().getSimpleName() + "] " + e.getMessage());
        return ResultResponse.fail(e.getHttpStatus(), e.getCode(), e.getMessage());
    }

}