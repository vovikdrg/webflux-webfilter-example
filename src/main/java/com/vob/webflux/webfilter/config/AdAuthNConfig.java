package com.vob.webflux.webfilter.config;

import com.vob.webflux.webfilter.filter.AdAuthNFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class AdAuthNConfig {
    @Value("${jwt.iss}")
    private String issuer;
    @Value("${jwt.aud}")
    private String aud;
    @Value("${jwt.jwk-uri}")
    private String jwkUrl;


    @Bean
    AdAuthNFilter createFilterBean() {
        return new AdAuthNFilter(this.issuer, this.aud, this.jwkUrl);
    }

}