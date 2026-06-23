package dev.barrikeit.security.config.filter;

import dev.barrikeit.security.config.SecurityProperties;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Log4j2
public class RateLimitingFilter extends OncePerRequestFilter {

  private static final List<String> RATE_LIMITED_SUFFIXES =
      List.of("/auth/login", "/auth/register", "/auth/refresh");

  private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
  private final boolean enabled;
  private final int capacity;
  private final int refillTokens;
  private final int refillPeriodMinutes;

  public RateLimitingFilter(SecurityProperties.RateLimitProperties props) {
    SecurityProperties.RateLimitProperties p =
        (props != null) ? props : new SecurityProperties.RateLimitProperties();
    this.enabled = p.isEnabled();
    this.capacity = p.getCapacity();
    this.refillTokens = p.getRefillTokens();
    this.refillPeriodMinutes = p.getRefillPeriodMinutes();
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {

    if (!enabled || !isRateLimited(request.getRequestURI())) {
      chain.doFilter(request, response);
      return;
    }

    String clientKey = resolveClientIp(request);
    Bucket bucket = buckets.computeIfAbsent(clientKey, k -> newBucket());

    if (bucket.tryConsume(1)) {
      chain.doFilter(request, response);
    } else {
      log.warn("Rate limit exceeded — ip={} path={}", clientKey, request.getRequestURI());
      response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      response
          .getWriter()
          .write(
              "{\"status\":429,\"error\":\"Too Many Requests\","
                  + "\"message\":\"Rate limit exceeded. Try again in "
                  + refillPeriodMinutes
                  + " minute(s).\"}");
    }
  }

  private boolean isRateLimited(String uri) {
    return RATE_LIMITED_SUFFIXES.stream().anyMatch(uri::endsWith);
  }

  private Bucket newBucket() {
    return Bucket.builder()
        .addLimit(
            Bandwidth.builder()
                .capacity(capacity)
                .refillGreedy(refillTokens, Duration.ofMinutes(refillPeriodMinutes))
                .build())
        .build();
  }

  private String resolveClientIp(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For");
    if (StringUtils.hasText(forwarded)) {
      return forwarded.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
