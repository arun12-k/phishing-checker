# Phishing Link Checker

A Chromium Manifest V3 extension with a Java 17 / Spring Boot URL risk API.

## Run the API

Requirements: Java 17+ and Maven 3.9+.

```sh
cd backend
mvn spring-boot:run
```

The API listens on `http://127.0.0.1:8080`. Check `GET /health` and send `POST /predict` with `{"url":"https://example.com" }`. The response contains a label (`legitimate`, `suspicious`, or `phishing`), a 0–1 risk score, risk level, and human-readable indicators. Existing clients that send a `features` object remain supported.

## Load the extension

Open `chrome://extensions`, enable Developer mode, select **Load unpacked**, and choose the `frontend` directory. Keep the Java API running for URL analysis.

## Build and verify

```sh
cd backend
mvn test
mvn package
```

Or build the container from the repository root with `docker build -f backend/Dockerfile -t phishing-checker backend`.

## Detection limits

The bundled detector is an explainable URL-feature heuristic. The original Python API depended on a `model.joblib` artifact that was absent from the repository, so it could not start reliably. This Java version needs no downloaded model or API key and does not claim to use a trained AI model, reputation database, page-content inspection, or certificate validation. Treat results as a warning signal, not a guarantee. The extension needs the local API for current checks.
