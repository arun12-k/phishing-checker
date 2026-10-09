package com.phishingchecker;

import java.net.IDN;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@CrossOrigin(origins = "*")
public class PredictionController {
    private static final Pattern IPV4 = Pattern.compile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    private static final List<String> BRAND_NAMES = List.of("paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "instagram", "whatsapp", "bank");

    public record PredictionRequest(String url, Map<String, Object> features) {}
    public record PredictionResponse(String label, double score, String riskLevel, List<String> indicators, String model) {}

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok", "service", "phishing-checker-java");
    }

    @PostMapping("/predict")
    public PredictionResponse predict(@RequestBody(required = false) PredictionRequest request) {
        if (request == null || ((request.url() == null || request.url().isBlank()) && (request.features() == null || request.features().isEmpty()))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Provide a URL or a non-empty features object.");
        }
        String url = request.url();
        if (url == null || url.isBlank()) {
            return scoreFeatures(request.features());
        }
        URI uri;
        try {
            String normalized = url.trim();
            if (!normalized.matches("(?i)^https?://.*")) normalized = "https://" + normalized;
            uri = URI.create(normalized);
            if (uri.getHost() == null || uri.getHost().isBlank() || uri.getUserInfo() != null) throw new IllegalArgumentException();
        } catch (RuntimeException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Enter a valid HTTP or HTTPS URL.");
        }

        String host = IDN.toASCII(uri.getHost()).toLowerCase(Locale.ROOT);
        String full = url.toLowerCase(Locale.ROOT);
        List<String> indicators = new ArrayList<>();
        double risk = 0.04;
        if (IPV4.matcher(host).matches()) { risk += 0.42; indicators.add("Uses an IP address instead of a domain name"); }
        if (host.startsWith("xn--") || host.contains(".xn--")) { risk += 0.38; indicators.add("Contains an internationalized domain that may imitate another site"); }
        if (uri.getUserInfo() != null || full.contains("@")) { risk += 0.42; indicators.add("Contains user-info or an @ symbol that can disguise the destination"); }
        int subdomains = Math.max(0, host.split("\\.").length - 2);
        if (subdomains >= 4) { risk += 0.19; indicators.add("Has an unusually deep subdomain chain"); }
        else if (subdomains >= 2) { risk += 0.07; indicators.add("Uses multiple subdomains"); }
        if (host.length() >  forty()) { risk += 0.16; indicators.add("Uses an unusually long hostname"); }
        if (url.length() > 120) { risk += 0.10; indicators.add("URL is unusually long"); }
        if (host.contains("-")) { risk += 0.07; indicators.add("Hostname contains hyphens"); }
        if (full.contains("%")) { risk += 0.06; indicators.add("Contains encoded characters"); }
        if (uri.getScheme().equalsIgnoreCase("http")) { risk += 0.10; indicators.add("Connection does not use HTTPS"); }
        if (count(full, '.') >= 5) { risk += 0.08; indicators.add("Contains many dot-separated URL segments"); }
        boolean brandInSubdomain = BRAND_NAMES.stream().anyMatch(b -> host.contains(b) && !host.equals(b + ".com") && !host.endsWith("." + b + ".com"));
        if (brandInSubdomain) { risk += 0.30; indicators.add("Uses a well-known brand name in a non-matching domain"); }
        for (String word : List.of("login", "signin", "verify", "secure", "update", "confirm", "password", "wallet", "account", "recovery")) {
            if (full.contains(word)) { risk += 0.07; indicators.add("Contains credential or account-action wording"); break; }
        }
        risk = Math.min(0.99, risk);
        String label = risk >= 0.68 ? "phishing" : risk >= 0.38 ? "suspicious" : "legitimate";
        return new PredictionResponse(label, round(risk), label.equals("phishing") ? "high" : label.equals("suspicious") ? "medium" : "low", List.copyOf(indicators), "Explainable URL risk model (heuristic; no external AI or threat-intelligence feed)");
    }

    private PredictionResponse scoreFeatures(Map<String, Object> f) {
        List<String> indicators = new ArrayList<>();
        double risk = 0.04;
        risk += feature(f, "IpAddress", 0.42, "Uses an IP address instead of a domain name", indicators);
        risk += feature(f, "AtSymbol", 0.42, "Contains an @ symbol that can disguise the destination", indicators);
        risk += feature(f, "NoHttps", 0.10, "Connection does not use HTTPS", indicators);
        risk += feature(f, "RandomString", 0.16, "Hostname may contain a randomly generated string", indicators);
        risk += feature(f, "NumSensitiveWords", 0.08, "Contains credential or account-action wording", indicators);
        risk += Math.min(0.18, numeric(f.get("SubdomainLevel")) * 0.045);
        risk += Math.min(0.15, Math.max(0, numeric(f.get("NumDashInHostname"))) * 0.03);
        risk += numeric(f.get("EmbeddedBrandName")) > 0 ? 0.30 : 0;
        risk = Math.min(0.99, risk);
        String label = risk >= 0.68 ? "phishing" : risk >= 0.38 ? "suspicious" : "legitimate";
        return new PredictionResponse(label, round(risk), label.equals("phishing") ? "high" : label.equals("suspicious") ? "medium" : "low", List.copyOf(indicators), "Explainable URL risk model (heuristic; no external AI or threat-intelligence feed)");
    }
    private static double feature(Map<String,Object> f, String key, double weight, String note, List<String> out) {
        if (numeric(f.get(key)) > 0) { out.add(note); return weight; }
        return 0;
    }
    private static double numeric(Object value) {
        if (value instanceof Number n) return Double.isFinite(n.doubleValue()) ? Math.max(0, Math.min(10000, n.doubleValue())) : 0;
        if (value instanceof String s) try { return Math.max(0, Math.min(10000, Double.parseDouble(s))); } catch (NumberFormatException ignored) { return 0; }
        return 0;
    }
    private static int count(String value, char c) { int n = 0; for (int i=0;i<value.length();i++) if (value.charAt(i)==c) n++; return n; }
    private static int forty() { return 40; }
    private static double round(double value) { return Math.round(value * 1000.0) / 1000.0; }
}
