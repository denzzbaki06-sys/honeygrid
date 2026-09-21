package com.honeygrid.honeygrid.service;

import org.springframework.stereotype.Service;

@Service
public class MitreMapperService {

    public static class MitreInfo {
        public String id;
        public String name;

        public MitreInfo(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }

    public MitreInfo mapAttackToMitre(String protocol, String payload) {
        if ("HTTP_BRUTE_FORCE".equals(protocol)) {
            return new MitreInfo("T1110", "Brute Force / Password Guessing");
        } else if ("SSH_ATTEMPT".equals(protocol)) {
            return new MitreInfo("T1046", "Network Service Discovery");
        } else if ("HTTP_ADMIN_PAGEVIEW".equals(protocol)) {
            return new MitreInfo("T1595", "Active Reconnaissance / Web Scanning");
        }
        return new MitreInfo("UNKNOWN", "No technique inferred");
    }
}