package dev.barrikeit.security.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import dev.barrikeit.security.config.SecurityProperties;
import dev.barrikeit.security.model.domain.BasicUserDetails;
import dev.barrikeit.security.model.domain.UserSession;
import dev.barrikeit.security.rest.dto.JwtDto;
import dev.barrikeit.security.rest.dto.LoginDto;
import dev.barrikeit.security.util.JwtUtil;
import dev.barrikeit.security.util.TokenType;
import dev.barrikeit.util.TimeUtil;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService")
class AuthServiceTest {

  @BeforeAll
  static void initTimeUtil() {
    new TimeUtil().setZoneStatic("UTC");
  }

  @Mock private SecurityProperties securityProperties;
  @Mock private BasicUserDetailsService basicUserDetailsService;
  @Mock private UserSessionService sessionService;
  @Mock private JwtUtil jwtUtil;
  @InjectMocks private AuthService authService;

  private UUID userId;
  private BasicUserDetails userDetails;
  private String accessToken;
  private String refreshToken;
  private String accessJti;
  private String refreshJti;

  @BeforeEach
  void setUp() {
    userId = UUID.randomUUID();
    accessJti = UUID.randomUUID().toString();
    refreshJti = UUID.randomUUID().toString();
    accessToken = "access.token.value";
    refreshToken = "refresh.token.value";
    userDetails =
        new BasicUserDetails(
            userId,
            "testuser",
            "encoded-password",
            true,
            false,
            List.of(new SimpleGrantedAuthority("US")),
            List.of());
  }

  @Test
  @DisplayName("login returns token pair for valid credentials")
  void login_validCredentials_returnsTokenPair() {
    LoginDto loginDto = new LoginDto("testuser", "password");
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(userDetails, null, List.of());

    when(basicUserDetailsService.authenticate(any())).thenReturn(auth);
    when(securityProperties.getMaxConcurrentSessions()).thenReturn(5);
    when(sessionService.activeSessions(userId, TokenType.ACCESS)).thenReturn(0L);
    when(jwtUtil.generateAccessToken(eq(userDetails), anyString())).thenReturn(accessToken);
    when(jwtUtil.generateRefreshToken(eq(userDetails), anyString())).thenReturn(refreshToken);
    when(jwtUtil.extractExpirationDate(accessToken)).thenReturn(new Date());
    when(jwtUtil.extractExpirationDate(refreshToken)).thenReturn(new Date());

    JwtDto result = authService.login(loginDto);

    assertThat(result.getToken()).isEqualTo(accessToken);
    assertThat(result.getRefreshToken()).isEqualTo(refreshToken);
    verify(sessionService, times(2)).createSession(any(), anyString(), anyString(), any(), any(), anyString());
  }

  @Test
  @DisplayName("login throws BadRequestException when max sessions exceeded")
  void login_maxSessionsExceeded_throws() {
    LoginDto loginDto = new LoginDto("testuser", "password");
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(userDetails, null, List.of());

    when(basicUserDetailsService.authenticate(any())).thenReturn(auth);
    when(securityProperties.getMaxConcurrentSessions()).thenReturn(1);
    when(sessionService.activeSessions(userId, TokenType.ACCESS)).thenReturn(1L);

    assertThatThrownBy(() -> authService.login(loginDto))
        .isInstanceOf(dev.barrikeit.util.exceptions.BadRequestException.class);
  }

  @Test
  @DisplayName("refresh rotates token pair when refresh token is valid")
  void refresh_validTokens_rotatesTokenPair() {
    UserSession session =
        UserSession.builder()
            .userId(userId)
            .jti(refreshJti)
            .jtiPair(accessJti)
            .issuedAt(OffsetDateTime.now())
            .expiresAt(OffsetDateTime.now().plusMinutes(15))
            .tokenType(TokenType.REFRESH.name())
            .build();

    when(jwtUtil.isRefreshableToken(refreshToken)).thenReturn(true);
    when(jwtUtil.extractUserId(refreshToken)).thenReturn(userId);
    when(jwtUtil.extractJti(refreshToken)).thenReturn(refreshJti);
    when(sessionService.findSession(userId, refreshJti)).thenReturn(session);
    when(jwtUtil.extractUserId(accessToken)).thenReturn(userId);
    when(jwtUtil.extractJti(accessToken)).thenReturn(accessJti);
    when(basicUserDetailsService.loadUserByCode(userId)).thenReturn(userDetails);
    when(securityProperties.getMaxConcurrentSessions()).thenReturn(5);
    when(sessionService.activeSessions(userId, TokenType.ACCESS)).thenReturn(0L);
    when(jwtUtil.generateAccessToken(eq(userDetails), anyString())).thenReturn("new.access.token");
    when(jwtUtil.generateRefreshToken(eq(userDetails), anyString())).thenReturn("new.refresh.token");
    when(jwtUtil.extractExpirationDate(anyString())).thenReturn(new Date());

    JwtDto result = authService.refresh(accessToken, refreshToken);

    assertThat(result.getToken()).isEqualTo("new.access.token");
    verify(sessionService).revokeTokenPair(userId, accessJti);
  }

  @Test
  @DisplayName("refresh throws BadCredentialsException for non-refreshable token")
  void refresh_nonRefreshableToken_throws() {
    when(jwtUtil.isRefreshableToken(refreshToken)).thenReturn(false);
    assertThatThrownBy(() -> authService.refresh(accessToken, refreshToken))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  @DisplayName("logout revokes the token pair")
  void logout_revokesSession() {
    when(jwtUtil.extractUserId(accessToken)).thenReturn(userId);
    when(jwtUtil.extractJti(accessToken)).thenReturn(accessJti);

    authService.logout(accessToken);

    verify(sessionService).revokeTokenPair(userId, accessJti);
  }
}
