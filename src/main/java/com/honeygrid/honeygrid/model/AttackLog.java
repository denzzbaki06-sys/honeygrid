package com.honeygrid.honeygrid.model;

import jakarta.persistence.*;
import java.util.Date;

@Entity
@Table(name = "attack_logs", indexes = @Index(name = "idx_attack_timestamp", columnList = "timestamp"))
public class AttackLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ipAddress;
    private int port;
    private String protocol;

    private String country;
    private String city;
    private double latitude;
    private double longitude;

    @Column(length = 2000)
    private String payload;

    // MITRE ATT&CK
    private String mitreTechniqueId;
    private String mitreTechniqueName;

    // FAZ 1 YENİ ALANLAR: Forensic & AI Analytics
    private String vulnerabilityCategory; // SQLi, XSS, Command_Injection, Reconnaissance vb.
    private int threatScore;              // 0 - 100 Arası Tehdit Skoru
    private String predictedIntent;      // SCRIPT_KIDDIE, AUTOMATED_SCANNER, APT_ADVANCED_ACTOR

    @Temporal(TemporalType.TIMESTAMP)
    private Date timestamp;

    public AttackLog() {}

    public AttackLog(String ipAddress, int port, String protocol, String country, String city,
                     double latitude, double longitude, String payload, String mitreTechniqueId,
                     String mitreTechniqueName, String vulnerabilityCategory, int threatScore,
                     String predictedIntent, Date timestamp) {
        this.ipAddress = ipAddress;
        this.port = port;
        this.protocol = protocol;
        this.country = country;
        this.city = city;
        this.latitude = latitude;
        this.longitude = longitude;
        this.payload = payload;
        this.mitreTechniqueId = mitreTechniqueId;
        this.mitreTechniqueName = mitreTechniqueName;
        this.vulnerabilityCategory = vulnerabilityCategory;
        this.threatScore = threatScore;
        this.predictedIntent = predictedIntent;
        this.timestamp = timestamp;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }
    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }
    public String getCity() { return city; }
    public void setCity(String city) { this.city = city; }
    public double getLatitude() { return latitude; }
    public void setLatitude(double latitude) { this.latitude = latitude; }
    public double getLongitude() { return longitude; }
    public void setLongitude(double longitude) { this.longitude = longitude; }
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    public String getMitreTechniqueId() { return mitreTechniqueId; }
    public void setMitreTechniqueId(String mitreTechniqueId) { this.mitreTechniqueId = mitreTechniqueId; }
    public String getMitreTechniqueName() { return mitreTechniqueName; }
    public void setMitreTechniqueName(String mitreTechniqueName) { this.mitreTechniqueName = mitreTechniqueName; }
    public String getVulnerabilityCategory() { return vulnerabilityCategory; }
    public void setVulnerabilityCategory(String vulnerabilityCategory) { this.vulnerabilityCategory = vulnerabilityCategory; }
    public int getThreatScore() { return threatScore; }
    public void setThreatScore(int threatScore) { this.threatScore = threatScore; }
    public String getPredictedIntent() { return predictedIntent; }
    public void setPredictedIntent(String predictedIntent) { this.predictedIntent = predictedIntent; }
    public Date getTimestamp() { return timestamp; }
    public void setTimestamp(Date timestamp) { this.timestamp = timestamp; }
}