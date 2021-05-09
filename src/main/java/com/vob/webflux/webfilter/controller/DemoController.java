package com.vob.webflux.webfilter.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class DemoController {
    @GetMapping("/greeting")
    public Mono<String> greeting(@RequestParam(value = "name", defaultValue = "World") String name) {
        return Mono.just(String.format("Hello, %s!", name));
    }
}
