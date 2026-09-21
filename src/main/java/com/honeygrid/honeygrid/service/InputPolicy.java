package com.honeygrid.honeygrid.service;

import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public final class InputPolicy {
    private InputPolicy() {}
    public static String ip(String input) {
        // Reject hostnames, CIDR, zone IDs and control characters before any parser can resolve DNS.
        if (input == null || input.length() > 45 || !input.matches("[0-9a-fA-F:.]+")
                || (!input.contains(":") && !input.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}"))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "IP literal required");
        }
        try { new IpAddressMatcher(input); }
        catch (IllegalArgumentException ex) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid IP literal"); }
        return input;
    }
    public static String payload(String input) {
        if (input == null || input.length() > 2000) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Payload limit is 2000 characters");
        return input;
    }
}
