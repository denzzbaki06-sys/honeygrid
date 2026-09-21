package com.honeygrid.honeygrid;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@org.springframework.scheduling.annotation.EnableScheduling
@SpringBootApplication
public class HoneygridApplication {

    public static void main(String[] args) {
        SpringApplication.run(HoneygridApplication.class, args);
    }
}