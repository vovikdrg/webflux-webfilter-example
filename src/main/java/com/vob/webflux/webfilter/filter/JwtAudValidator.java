package com.vob.webflux.webfilter.filter;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class JwtAudValidator implements OAuth2TokenValidator<Jwt> {
    private final String aud;
    private final OAuth2Error error;

    public JwtAudValidator(String aud) {
        this.aud = aud;
        this.error = new OAuth2Error("invalid_request", "The aud claim is not valid", "https://tools.ietf.org/html/rfc6750#section-3.1");

    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (jwt.getAudience().contains(aud)) {
            return OAuth2TokenValidatorResult.success();
        } else {
            return OAuth2TokenValidatorResult.failure(this.error);
        }
    }
}
