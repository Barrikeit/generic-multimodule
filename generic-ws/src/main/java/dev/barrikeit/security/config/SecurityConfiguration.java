package dev.barrikeit.security.config;

import dev.barrikeit.config.ApplicationProperties;
import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * WebSocket security configuration — session-aware JWT model.
 *
 * <h2>Why this differs from generic-rest</h2>
 *
 * <p><b>generic-rest</b> uses {@code STATELESS}: every HTTP request carries a Bearer token;
 * {@code JwtFilter} validates it on each call; no session is ever created.
 *
 * <p><b>generic-ws</b> uses {@code IF_REQUIRED}: JWT is validated <em>once</em> at STOMP
 * {@code CONNECT} time by {@link dev.barrikeit.security.config.interceptor.JwtChannelInterceptor}.
 * After the CONNECT frame is accepted, Spring's messaging infrastructure stores the authenticated
 * {@code Principal} in the STOMP session; all subsequent frames reuse it without re-validating.
 *
 * <h2>Why IF_REQUIRED is required (not STATELESS)</h2>
 * <ol>
 *   <li>The HTTP WebSocket upgrade request needs a session so Spring Security can propagate the
 *       security context into the WebSocket/STOMP layer.</li>
 *   <li>SockJS HTTP long-polling fallback uses the session to correlate poll requests with the
 *       logical channel. With {@code STATELESS}, SockJS fallback breaks entirely.</li>
 *   <li>Spring's STOMP security context propagation is session-backed at the HTTP upgrade layer.</li>
 * </ol>
 *
 * <h2>No JwtFilter on the HTTP chain</h2>
 * <p>There is deliberately NO {@code JwtFilter} added here. WebSocket frames are not HTTP requests
 * once the connection is upgraded; authentication is handled at the STOMP channel level by
 * {@code JwtChannelInterceptor}. The small number of plain HTTP endpoints in this app
 * ({@code /version}, {@code /actuator/health}) are either {@code permitAll} or rely on
 * {@code @PreAuthorize} method security.
 *
 * <h2>Revocation safety</h2>
 * <p>Because JWT expiry is only checked at CONNECT time, a mid-session revoked token would keep
 * the existing WS connection alive. Mitigation: {@code JwtChannelInterceptor} calls
 * {@code UserSessionService.validateToken()} against the DB. Delete the {@code UserSession} row
 * server-side to reject the next CONNECT attempt.
 */
@Log4j2
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity // enables @PreAuthorize on @MessageMapping methods
@ConditionalOnProperty(name = "security.enabled", havingValue = "true", matchIfMissing = true)
@Import(SecurityExceptionHandler.class)
public class SecurityConfiguration {

  private final ApplicationProperties.ServerProperties serverProperties;
  private final SecurityProperties securityProperties;
  private final SecurityExceptionHandler exceptionHandler;

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    log.warn("WS SecurityConfiguration active — IF_REQUIRED sessions, JWT validated at STOMP CONNECT");
    String apiPath = serverProperties.getServlet().getApiPath();

    http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .csrf(AbstractHttpConfigurer::disable)
        .headers(
            headers ->
                headers
                    // SockJS iframes need same-origin framing
                    .frameOptions(options -> options.sameOrigin())
                    // connect-src must include ws:/wss: for browsers to allow WebSocket
                    .contentSecurityPolicy(
                        csp -> csp.policyDirectives(
                            "default-src 'self'; connect-src 'self' ws: wss:"))
                    .addHeaderWriter(
                        new StaticHeadersWriter("Referrer-Policy", "strict-origin-when-cross-origin"))
                    .addHeaderWriter(
                        new StaticHeadersWriter(
                            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
                    .addHeaderWriter(
                        new StaticHeadersWriter("Cross-Origin-Opener-Policy", "same-origin")))
        // IF_REQUIRED: allow session creation for the WS HTTP upgrade and SockJS fallback.
        // JWT validation itself lives in JwtChannelInterceptor at the STOMP channel level.
        .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
        .exceptionHandling(
            ex ->
                ex.authenticationEntryPoint(exceptionHandler)
                    .accessDeniedHandler(exceptionHandler))
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(HttpMethod.OPTIONS, "/**")
                    .permitAll()
                    .requestMatchers(
                        // WebSocket handshake — permit at HTTP level;
                        // real authentication happens at STOMP CONNECT via JwtChannelInterceptor
                        apiPath + "/ws/**",
                        apiPath + "/public/**",
                        apiPath + "/error/**",
                        apiPath + "/error",
                        apiPath + "/version/**",
                        apiPath + "/version")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .httpBasic(Customizer.withDefaults());

    // No JwtFilter — auth is at the STOMP channel level, not the HTTP filter chain.

    return http.build();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    SecurityProperties.CorsProperties cors = securityProperties.getCors();

    if (Boolean.TRUE.equals(cors.getEnabled())) {
      configuration.setAllowedOriginPatterns(splitTrimmed(cors.getAllowed().getOrigins()));
      configuration.setAllowedMethods(splitTrimmed(cors.getAllowed().getMethods()));
      configuration.setAllowedHeaders(splitTrimmed(cors.getAllowed().getHeaders()));
      configuration.setAllowCredentials(true);
    }

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration(cors.getPath().getPattern(), configuration);
    return source;
  }

  private static List<String> splitTrimmed(String csv) {
    return Arrays.stream(csv.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();
  }
}
