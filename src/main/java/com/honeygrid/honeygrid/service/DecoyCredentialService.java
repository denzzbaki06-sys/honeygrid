package com.honeygrid.honeygrid.service;

import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.UUID;

@Service
public class DecoyCredentialService {

    public Map<String, String> generateDecoyCredentials(String ipAddress) {
        String decoyAwsAccessKey = "AKIA" + UUID.randomUUID().toString().replace("-", "").substring(0, 16).toUpperCase();
        String decoyAwsSecret = UUID.randomUUID().toString().replace("-", "") + "DecoySecretKey";
        String decoyDbPass = "HoneyGrid_Root_Pass_" + (int)(Math.random() * 9000 + 1000);

        return Map.of(
                "AWS_ACCESS_KEY_ID", decoyAwsAccessKey,
                "AWS_SECRET_ACCESS_KEY", decoyAwsSecret,
                "DATABASE_URL", "jdbc:postgresql://db-internal.honeygrid.io:5432/production_db",
                "DATABASE_PASSWORD", decoyDbPass
        );
    }
}