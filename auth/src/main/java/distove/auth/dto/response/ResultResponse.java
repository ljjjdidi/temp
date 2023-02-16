package distove.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Getter
@Builder
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResultResponse<T> {

    private int status;
    private String code;
    private String message;
    private T data;

    public static <T> ResponseEntity<Object> success(HttpStatus httpStatus, String message, T data) {
        return ResponseEntity
                .status(httpStatus)
                .body(ResultResponse.builder()
                        .status(httpStatus.value())
                        .message(message)
                        .data(data)
                        .build());
    }

    public static ResponseEntity<Object> fail(HttpStatus httpStatus, String code, String message) {
        return ResponseEntity
                .status(httpStatus)
                .body(ResultResponse.builder()
                        .status(httpStatus.value())
                        .code(code)
                        .message(message)
                        .build());
    }
}