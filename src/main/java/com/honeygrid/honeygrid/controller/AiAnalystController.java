package com.honeygrid.honeygrid.controller;
import com.honeygrid.honeygrid.service.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/soc-ai")
public class AiAnalystController {
    private final PayloadInspectorService inspector;
    private final AttackIntentAiService scoring;
    private final SoarPlaybookService soar;
    public AiAnalystController(PayloadInspectorService inspector, AttackIntentAiService scoring, SoarPlaybookService soar) {
        this.inspector=inspector; this.scoring=scoring; this.soar=soar;
    }
    public record AnalysisRequest(@NotBlank @Size(max=45) String ip, @NotNull @Size(max=2000) String payload) {}
    @PostMapping("/analyze-payload")
    public Map<String,Object> analyzePayloadWithAi(@Valid @RequestBody AnalysisRequest request) {
        InputPolicy.ip(request.ip());
        String category=inspector.inspectPayload(request.payload());
        var result=scoring.analyzeAttack(category,false,request.payload());
        return Map.of("mode", "RULE_BASED", "category", category, "threatScore", result.threatScore,
            "predictedIntent",result.predictedIntent, "threatActor","UNKNOWN",
            "analystRecommendation", "Heuristic analysis: " + category + "; score " + result.threatScore
                + "/100. Review the original event before responding. This is not AI inference or verified actor attribution.");
    }
    @PostMapping("/execute-containment")
    public ResponseEntity<Map<String,String>> executeContainment(@RequestParam String ip) {
        return ResponseEntity.status(501).body(soar.executeContainmentPlaybook(ip));
    }
}
