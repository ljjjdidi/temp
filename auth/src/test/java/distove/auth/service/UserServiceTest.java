package distove.auth.service;

import distove.auth.repoisitory.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@SpringBootTest
class UserServiceTest {
    @Autowired
    UserService userService;
    @Autowired
    private UserRepository userRepository;

    @Test
    void 회원가입() {
        // given

        // when

        // then
    }

    @Test
    void login() {
    }

    @Test
    void checkEmailDuplicate() {
    }

    @Test
    void checkNicknameDuplicate() {
    }
}