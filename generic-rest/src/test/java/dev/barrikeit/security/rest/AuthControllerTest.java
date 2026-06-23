package dev.barrikeit.security.rest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.barrikeit.security.rest.dto.JwtDto;
import dev.barrikeit.security.rest.dto.LoginDto;
import dev.barrikeit.security.rest.dto.RegisterDto;
import dev.barrikeit.security.service.AuthService;
import dev.barrikeit.util.TimeUtil;
import java.util.Date;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@WebMvcTest(AuthController.class)
@Import(AuthControllerTest.TestSecurityConfig.class)
@DisplayName("AuthController")
class AuthControllerTest {

  @TestConfiguration
  static class TestSecurityConfig {
    @Bean
    SecurityFilterChain testFilterChain(HttpSecurity http) throws Exception {
      return http
          .csrf(AbstractHttpConfigurer::disable)
          .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
          .build();
    }
  }

  @BeforeAll
  static void initTimeUtil() {
    new TimeUtil().setZoneStatic("UTC");
  }

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;
  @MockitoBean private AuthService authService;

  private static final String BASE = "/api/v1/auth";

  @Test
  @DisplayName("POST /auth/login returns 200 with token pair")
  void login_validCredentials_returns200() throws Exception {
    LoginDto request = new LoginDto("testuser", "Password1@");
    JwtDto response =
        JwtDto.builder()
            .token("access.token")
            .refreshToken("refresh.token")
            .expireAt(new Date())
            .expireRefreshAt(new Date())
            .build();
    when(authService.login(any(LoginDto.class))).thenReturn(response);

    mockMvc
        .perform(
            post(BASE + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.content.token").value("access.token"))
        .andExpect(jsonPath("$.content.refreshToken").value("refresh.token"));
  }

  @Test
  @DisplayName("POST /auth/register returns 200 with verification token")
  void register_validPayload_returns200() throws Exception {
    RegisterDto request = new RegisterDto("newuser", "new@example.com", "Password1@");
    when(authService.register(any(RegisterDto.class))).thenReturn("verification-token");

    mockMvc
        .perform(
            post(BASE + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("POST /auth/logout returns 200 for authenticated user")
  void logout_authenticatedUser_returns200() throws Exception {
    doNothing().when(authService).logout(anyString());

    mockMvc
        .perform(
            post(BASE + "/logout")
                .header("Authorization", "Bearer some.access.token"))
        .andExpect(status().isOk());
  }
}
