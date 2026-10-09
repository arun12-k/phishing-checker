package com.phishingchecker;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** CLI trainer for URL,Label CSV files or ZIP archives containing one. */
public final class ModelTrainer {
    private ModelTrainer() {}

    public static void main(String[] args) throws Exception {
        Path input = Path.of(args.length > 0 ? args[0] : "phishing_site_urls.csv.zip");
        Path output = Path.of(args.length > 1 ? args[1] : "model/url-char-ngram.bin");
        int epochs = args.length > 2 ? Integer.parseInt(args[2]) : 5;
        Dataset dataset = load(input);
        if (dataset.urls.size() < 100) throw new IllegalArgumentException("At least 100 valid labeled rows are required.");

        List<Integer> good = new ArrayList<>();
        List<Integer> bad = new ArrayList<>();
        for (int i = 0; i < dataset.urls.size(); i++) (dataset.labels.get(i) == 1 ? bad : good).add(i);
        if (good.size() < 2 || bad.size() < 2) throw new IllegalArgumentException("Dataset must include both good and bad URLs.");

        java.util.Random random = new java.util.Random(42);
        Collections.shuffle(good, random);
        Collections.shuffle(bad, random);
        List<Integer> train = new ArrayList<>();
        List<Integer> test = new ArrayList<>();
        splitClass(good, train, test);
        splitClass(bad, train, test);

        String[] trainUrls = new String[train.size()];
        int[] trainLabels = new int[train.size()];
        for (int i = 0; i < train.size(); i++) {
            int index = train.get(i);
            trainUrls[i] = dataset.urls.get(index);
            trainLabels[i] = dataset.labels.get(index);
        }

        System.out.printf(Locale.ROOT, "Rows: %d (%d good, %d bad); train: %d, test: %d%n",
                dataset.urls.size(), good.size(), bad.size(), train.size(), test.size());
        System.out.println("Training character n-gram logistic regression...");
        UrlNgramModel model = UrlNgramModel.train(trainUrls, trainLabels, epochs, 42);
        Metrics metrics = evaluate(model, dataset, test);
        model.save(output);
        System.out.printf(Locale.ROOT,
                "Holdout accuracy %.4f | precision %.4f | recall %.4f | F1 %.4f%n",
                metrics.accuracy(), metrics.precision(), metrics.recall(), metrics.f1());
        System.out.println("Saved trained Java model to " + output.toAbsolutePath());
    }

    private static void splitClass(List<Integer> source, List<Integer> train, List<Integer> test) {
        int trainSize = Math.max(1, (int) Math.floor(source.size() * 0.8));
        train.addAll(source.subList(0, trainSize));
        test.addAll(source.subList(trainSize, source.size()));
    }

    private static Dataset load(Path path) throws IOException {
        List<String> urls = new ArrayList<>();
        List<Integer> labels = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        InputStream file = Files.newInputStream(path);
        InputStream content = path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".zip")
                ? zipCsv(file) : file;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(content, StandardCharsets.UTF_8), 1 << 16)) {
            String headerLine = reader.readLine();
            if (headerLine == null) throw new IOException("Dataset is empty.");
            List<String> header = parseCsv(headerLine.replace("\uFEFF", ""));
            int urlColumn = findColumn(header, "url");
            int labelColumn = findColumn(header, "label");
            if (urlColumn < 0 || labelColumn < 0) {
                throw new IOException("Expected columns named URL and Label. Found: " + header);
            }
            String line;
            int rowNumber = 1;
            int invalid = 0;
            while ((line = reader.readLine()) != null) {
                rowNumber++;
                List<String> row = parseCsv(line);
                if (row.size() <= Math.max(urlColumn, labelColumn)) { invalid++; continue; }
                String url = row.get(urlColumn).trim();
                if (url.isEmpty()) { invalid++; continue; }
                int label;
                try { label = parseLabel(row.get(labelColumn)); }
                catch (IllegalArgumentException ex) { invalid++; continue; }
                if (seen.add(url)) {
                    urls.add(url);
                    labels.add(label);
                }
            }
            if (invalid > 0) System.out.println("Skipped " + invalid + " malformed, empty, or unsupported-label rows.");
        }
        return new Dataset(urls, labels);
    }

    private static InputStream zipCsv(InputStream file) throws IOException {
        ZipInputStream zip = new ZipInputStream(file, StandardCharsets.UTF_8);
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            if (!entry.isDirectory() && entry.getName().toLowerCase(Locale.ROOT).endsWith(".csv")) return zip;
        }
        zip.close();
        throw new IOException("ZIP archive contains no CSV file.");
    }

    private static int findColumn(List<String> header, String expected) {
        for (int i = 0; i < header.size(); i++) {
            if (header.get(i).trim().equalsIgnoreCase(expected)) return i;
        }
        return -1;
    }

    private static int parseLabel(String value) {
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "bad", "phishing", "malicious" -> 1;
            case "good", "legitimate", "benign", "safe" -> 0;
            default -> throw new IllegalArgumentException("Unsupported label: " + value);
        };
    }

    static List<String> parseCsv(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    field.append('"');
                    i++;
                } else {
                    quoted = !quoted;
                }
            } else if (c == ',' && !quoted) {
                fields.add(field.toString());
                field.setLength(0);
            } else {
                field.append(c);
            }
        }
        fields.add(field.toString());
        return fields;
    }

    private static Metrics evaluate(UrlNgramModel model, Dataset dataset, List<Integer> test) {
        int tp = 0, fp = 0, tn = 0, fn = 0;
        for (int index : test) {
            boolean predictedBad = model.phishingProbability(dataset.urls.get(index)) >= 0.5;
            boolean actualBad = dataset.labels.get(index) == 1;
            if (predictedBad && actualBad) tp++;
            else if (predictedBad) fp++;
            else if (actualBad) fn++;
            else tn++;
        }
        double precision = divide(tp, tp + fp);
        double recall = divide(tp, tp + fn);
        return new Metrics(divide(tp + tn, test.size()), precision, recall, divide(2 * precision * recall, precision + recall));
    }

    private static double divide(double n, double d) { return d == 0 ? 0 : n / d; }
    private record Dataset(List<String> urls, List<Integer> labels) {}
    private record Metrics(double accuracy, double precision, double recall, double f1) {}
}
