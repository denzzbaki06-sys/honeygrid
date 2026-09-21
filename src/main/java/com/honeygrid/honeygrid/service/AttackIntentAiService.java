package com.honeygrid.honeygrid.service;

import org.springframework.stereotype.Service;

@Service
public class AttackIntentAiService {

    public static class IntentAnalysisResult {
        public int threatScore;
        public String predictedIntent;

        public IntentAnalysisResult(int threatScore, String predictedIntent) {
            this.threatScore = threatScore;
            this.predictedIntent = predictedIntent;
        }
    }

    public IntentAnalysisResult analyzeAttack(String vulnCategory, boolean isBlocked, String payload) {
        int baseScore = 30;
        String intent = "AUTOMATED_BOT_SCANNER";

        switch (vulnCategory) {
            case "COMMAND_INJECTION":
                baseScore += 50;
                intent = "POSSIBLE_COMMAND_EXECUTION";
                break;
            case "SQL_INJECTION":
                baseScore += 40;
                intent = "DATABASE_EXFILTRATION_ATTEMPT";
                break;
            case "CROSS_SITE_SCRIPTING_XSS":
                baseScore += 40;
                intent = "POSSIBLE_BROWSER_SCRIPT_EXECUTION";
                break;
            case "DIRECTORY_TRAVERSAL":
                baseScore += 35;
                intent = "SYSTEM_RECONNAISSANCE";
                break;
            case "CREDENTIAL_BRUTE_FORCE":
                baseScore += 25;
                intent = "POSSIBLE_PASSWORD_GUESSING";
                break;
            default:
                baseScore += 10;
                break;
        }

        if (isBlocked) {
            baseScore += 20;
        }

        if (payload != null && payload.length() > 80) {
            baseScore += 10; // Karmaşık zararlı yük bonusu
        }

        int finalScore = Math.min(baseScore, 100);
        return new IntentAnalysisResult(finalScore, intent);
    }
}