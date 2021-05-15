package com.vob.webflux.webfilter.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

@Component
public class AdAuthNFilter implements WebFilter {
    private final String AuthHeader = "X-Server-Authorization";
    public static final String HEADER_PREFIX = "Bearer ";
    private final ReactiveJwtDecoder jwtDecoder;

    public AdAuthNFilter(@Value("${jwt.iss}")  String issuer, @Value("${jwt.aud}") String aud, @Value("${jwt.jwk-uri}") String jwkUrl) {
        jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkUrl).build();
        ((NimbusReactiveJwtDecoder) jwtDecoder).setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtAudValidator(aud),
                new JwtIssuerValidator(issuer),
                new JwtTimestampValidator()));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return Mono
                .defer(() -> {
                    var token = resolveToken(exchange.getRequest());
                    if (!StringUtils.hasText(token)) {
                        throw new BadJwtException("Authorisation token is invalid");
                    }
                    return jwtDecoder.decode(token);
                })
                .flatMap(tokenJwt -> chain.filter(exchange))
                .onErrorResume(JwtValidationException.class, err -> handleError(exchange, err))
                .onErrorResume(err -> handleError(exchange, err));
    }

    private Mono<Void> handleError(ServerWebExchange exchange, JwtValidationException ex) {
        return writeResponse(exchange, ex.getErrors().stream().map(OAuth2Error::getDescription).collect(Collectors.joining(", ")));
    }
    private Mono<Void> handleError(ServerWebExchange exchange, Throwable ex) {
       return writeResponse(exchange, ex.getMessage());
    }

    private Mono<Void> writeResponse(ServerWebExchange exchange, String message) {
        exchange.getResponse().setRawStatusCode(HttpStatus.UNAUTHORIZED.value());
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        return exchange
                .getResponse()
                .writeWith(
                        Flux.just(
                                exchange.getResponse().bufferFactory().wrap(message.getBytes(StandardCharsets.UTF_8))));
    }

    private String resolveToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(AuthHeader);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(HEADER_PREFIX)) {
            return bearerToken.substring(7).trim();
        }
        return "";
    }
}