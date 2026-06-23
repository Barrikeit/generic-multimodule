package dev.barrikeit.security.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import dev.barrikeit.security.model.domain.UserSession;
import dev.barrikeit.security.model.repository.UserSessionRepository;
import dev.barrikeit.security.util.TokenType;
import dev.barrikeit.util.exceptions.NotFoundException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserSessionService")
class UserSessionServiceTest {

  @Mock private UserSessionRepository repository;
  @InjectMocks private UserSessionService service;

  private UUID userId;
  private String jti;
  private String jtiPair;
  private UserSession session;

  @BeforeEach
  void setUp() {
    userId = UUID.randomUUID();
    jti = UUID.randomUUID().toString();
    jtiPair = UUID.randomUUID().toString();
    OffsetDateTime now = OffsetDateTime.now();
    session =
        UserSession.builder()
            .userId(userId)
            .jti(jti)
            .jtiPair(jtiPair)
            .issuedAt(now)
            .expiresAt(now.plusMinutes(10))
            .tokenType(TokenType.ACCESS.name())
            .build();
  }

  @Test
  @DisplayName("createSession persists a new session")
  void createSession_savesSession() {
    OffsetDateTime now = OffsetDateTime.now();
    service.createSession(userId, jti, jtiPair, now, now.plusMinutes(10), TokenType.ACCESS.name());
    verify(repository).save(any(UserSession.class));
  }

  @Test
  @DisplayName("validateToken returns true when session exists")
  void validateToken_existingSession_returnsTrue() {
    when(repository.existsByUserIdAndJti(userId, jti)).thenReturn(true);
    assertThat(service.validateToken(userId, jti)).isTrue();
  }

  @Test
  @DisplayName("validateToken returns false when session does not exist")
  void validateToken_missingSession_returnsFalse() {
    when(repository.existsByUserIdAndJti(userId, jti)).thenReturn(false);
    assertThat(service.validateToken(userId, jti)).isFalse();
  }

  @Test
  @DisplayName("findSession throws NotFoundException when session missing")
  void findSession_missing_throwsNotFound() {
    when(repository.findByUserIdAndJti(userId, jti)).thenReturn(Optional.empty());
    assertThatThrownBy(() -> service.findSession(userId, jti))
        .isInstanceOf(NotFoundException.class);
  }

  @Test
  @DisplayName("findSession returns session when it exists")
  void findSession_found_returnsSession() {
    when(repository.findByUserIdAndJti(userId, jti)).thenReturn(Optional.of(session));
    UserSession result = service.findSession(userId, jti);
    assertThat(result.getJti()).isEqualTo(jti);
  }

  @Test
  @DisplayName("activeSessions delegates count to repository")
  void activeSessions_delegatesToRepository() {
    when(repository.countByUserIdAndTokenType(userId, TokenType.ACCESS.name())).thenReturn(2);
    assertThat(service.activeSessions(userId, TokenType.ACCESS)).isEqualTo(2);
  }

  @Test
  @DisplayName("revokeTokenPair deletes both access and refresh sessions")
  void revokeTokenPair_deletesBothTokens() {
    when(repository.findByUserIdAndJti(userId, jti)).thenReturn(Optional.of(session));
    service.revokeTokenPair(userId, jti);
    verify(repository).deleteByUserIdAndJti(userId, jti);
    verify(repository).deleteByUserIdAndJti(userId, jtiPair);
  }

  @Test
  @DisplayName("revokeAll delegates deleteByUserId to repository")
  void revokeAll_deletesAllUserSessions() {
    service.revokeAll(userId);
    verify(repository).deleteByUserId(userId);
  }

  @Test
  @DisplayName("findUserSessions delegates to repository")
  void findUserSessions_returnsAll() {
    when(repository.findAllByUserId(userId)).thenReturn(List.of(session));
    List<UserSession> result = service.findUserSessions(userId);
    assertThat(result).hasSize(1);
  }
}
