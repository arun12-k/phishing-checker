# Phishing Link Checker

A Chromium Manifest V3 extension backed by a Java 17 / Spring Boot API and a trainable URL text-classification model.

## Train the Java AI model

The training data stays local and is not committed to Git. The trainer accepts a CSV or ZIP containing a CSV with `URL` and `Label` columns. It recognizes labels such as `bad` / `good`, `phishing` / `legitimate`, and `malicious` / `benign`. It reports skipped rows and class counts, makes a stratified 80/20 holdout split, prints accuracy, precision, recall, and F1, and writes a compact binary model.

From the `backend` directory, run:

```powershell
mvn test package
java -cp target/classes com.phishingchecker.ModelTrainer "C:\path\to\phishing_site_urls.csv.zip" "model\url-char-ngram.bin" 5
$env:PHISHING_MODEL_PATH = "model/url-char-ngram.bin"
mvn spring-boot:run
```

The trainer uses Java character 3–5-gram feature hashing and class-weighted logistic regression. It needs no Python, third-party ML runtime, network service, or API key. Do not commit the dataset or trained artifact; keep the artifact available to the API process via `PHISHING_MODEL_PATH`.

## Run the API

Requirements: Java 17+ and Maven 3.9+.

```sh
cd backend
mvn spring-boot:run
```

The API listens on `http://127.0.0.1:8080`. Check `GET /health` and send `POST /predict` with `{"url":"https://example.com" }`. The response contains a label (`legitimate` or `phishing`), a 0–1 model score, risk level, and indicators. The existing `features` request format is still accepted for compatibility.

If a trained model artifact is present at `PHISHING_MODEL_PATH` (default `model/url-char-ngram.bin` relative to the backend working directory), the API uses it. Without an artifact, the API reports its heuristic fallback in the response; it does not claim that fallback is AI.

## Load the extension

Open `chrome://extensions`, enable Developer mode, select **Load unpacked**, and choose the `frontend` directory. Keep the Java API running for URL analysis.

## Build and verify

```sh
cd backend
mvn test
mvn package
```

GitHub Actions also runs the Java tests/build and validates the extension JavaScript syntax and manifest. Or build the API container from the repository root with `docker build -f backend/Dockerfile -t phishing-checker backend`.

## Detection limits

The trained model learns patterns in labeled URL strings. It does not inspect page HTML, WHOIS/domain age, live reputation feeds, or TLS certificates. Its holdout metrics measure performance on this dataset split and do not guarantee real-world detection; duplicates or source overlap can make the estimate optimistic. Treat results as a warning signal, not a guarantee.
