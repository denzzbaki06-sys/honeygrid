package com.honeygrid.honeygrid.service;
import org.springframework.stereotype.Service;
@Service
public class GeoIpService {
    // Location is deliberately unknown until a verified local database/provider is configured.
    public GeoDetails getIpDetails(String ipAddress) { return new GeoDetails("Unknown", "Unknown", 0, 0); }
    public record GeoDetails(String country,String city,double latitude,double longitude) {
        public String getCountry() { return country; }
        public String getCity() { return city; }
        public double getLatitude() { return latitude; }
        public double getLongitude() { return longitude; }
    }
}
