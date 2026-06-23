package dev.barrikeit.security.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.barrikeit.security.config.SecurityProperties;
import dev.barrikeit.security.model.domain.BasicUserDetails;
import dev.barrikeit.util.TimeUtil;
import io.jsonwebtoken.ExpiredJwtException;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@DisplayName("JwtUtil")
class JwtUtilTest {

  private JwtUtil jwtUtil;
  private BasicUserDetails user;

  @BeforeAll
  static void initTimeUtil() {
    // TimeUtil.zone is normally injected by Spring @Value; set it manually for unit tests.
    new TimeUtil().setZoneStatic("UTC");
  }

  @BeforeEach
  void setUp() {
    SecurityProperties props = new SecurityProperties();
    SecurityProperties.JwtProperties jwt = new SecurityProperties.JwtProperties();
    jwt.setSecret("generic-test-secret-must-be-at-least-32-chars-long-for-hmac");
    jwt.setIssuer("test-issuer");
    jwt.setExpiration(600);
    jwt.setExpirationRefresh(900);
    props.setJwt(jwt);
    jwtUtil = new JwtUtil(props);

    UUID id = UUID.randomUUID();
    user =
        new BasicUserDetails(
            id,
            "testuser",
            "encoded-password",
            true,
            false,
            List.of(new SimpleGrantedAuthority("US")),
            List.of(new SimpleGrantedAuthority("US_MOD")));
  }

  @Test
  @DisplayName("access token contains correct subject and userId")
  void generateAccessToken_containsExpectedClaims() {
    String jti = UUID.randomUUID().toString();
    String token = jwtUtil.generateAccessToken(user, jti);

    assertThat(jwtUtil.extractUsername(token)).isEqualTo(user.getUsername());
    assertThat(jwtUtil.extractUserId(token)).isEqualTo(user.getId());
    assertThat(jwtUtil.extractJti(token)).isEqualTo(jti);
  }

  @Test
  @DisplayName("access token is not refreshable")
  void generateAccessToken_isNotRefreshable() {
    String token = jwtUtil.generateAccessToken(user, UUID.randomUUID().toString());
    assertThat(jwtUtil.isRefreshableToken(token)).isFalse();
  }

  @Test
  @DisplayName("refresh token is refreshable")
  void generateRefreshToken_isRefreshable() {
    String token = jwtUtil.generateRefreshToken(user, UUID.randomUUID().toString());
    assertThat(jwtUtil.isRefreshableToken(token)).isTrue();
  }

  @Test
  @DisplayName("extractAuthorities returns role-based authorities")
  void extractAuthorities_returnsRoles() {
    String token = jwtUtil.generateAccessToken(user, UUID.randomUUID().toString());
    List<SimpleGrantedAuthority> authorities = jwtUtil.extractAuthorities(token);
    assertThat(authorities).isNotEmpty();
    assertThat(authorities.stream().map(SimpleGrantedAuthority::getAuthority))
        .contains("US");
  }

  @Test
  @DisplayName("expired token raises ExpiredJwtException")
  void parseToken_withExpiredToken_throwsException() {
    SecurityProperties props = new SecurityProperties();
    SecurityProperties.JwtProperties jwt = new SecurityProperties.JwtProperties();
    jwt.setSecret("generic-test-secret-must-be-at-least-32-chars-long-for-hmac");
    jwt.setIssuer("test-issuer");
    jwt.setExpiration(0);
    jwt.setExpirationRefresh(0);
    props.setJwt(jwt);
    JwtUtil expiredUtil = new JwtUtil(props);

    String token = expiredUtil.generateAccessToken(user, UUID.randomUUID().toString());

    assertThatThrownBy(() -> expiredUtil.parseToken(token))
        .isInstanceOf(ExpiredJwtException.class);
  }

  @Test
  @DisplayName("extractExpirationDate returns a future date for fresh tokens")
  void extractExpirationDate_isFuture() {
    String token = jwtUtil.generateAccessToken(user, UUID.randomUUID().toString());
    assertThat(jwtUtil.extractExpirationDate(token))
        .isAfter(jwtUtil.extractIssuedDate(token));
  }
}
