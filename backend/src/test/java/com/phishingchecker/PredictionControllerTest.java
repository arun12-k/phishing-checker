package com.phishingchecker;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class PredictionControllerTest {
    private final PredictionController controller = new PredictionController();

    @Test void flagsCredentialStealingIpUrl() {
        var result = controller.predict(new PredictionController.PredictionRequest("http://192.0.2.1/login/verify", null));
        assertEquals("phishing", result.label());
        assertTrue(result.score() >= 0.68);
        assertFalse(result.indicators().isEmpty());
    }
    @Test void givesLowRiskForOrdinarySecureDomain() {
        var result = controller.predict(new PredictionController.PredictionRequest("https://www.example.com/about", null));
        assertEquals("legitimate", result.label());
        assertTrue(result.score() < 0.38);
    }
    @Test void supportsLegacyFeaturePayload() {
        var result = controller.predict(new PredictionController.PredictionRequest(null, java.util.Map.of("IpAddress", 1)));
        assertEquals("suspicious", result.label());
        assertTrue(result.score() >= 0.38);
    }
}
