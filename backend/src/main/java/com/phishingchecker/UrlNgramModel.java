package com.phishingchecker;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;

/**
 * Supervised URL text classifier: hashed character n-grams + online logistic regression.
 * The feature space and training code are implemented in Java; the saved model is portable
 * across runs and does not require Python or an external service.
 */
public final class UrlNgramModel {
    private static final int MAGIC = 0x50484331; // PHC1
    private static final int VERSION = 1;
    private static final int DIMENSIONS = 1 << 18;
    private static final int MAX_URL_LENGTH = 2048;
    private static final double L2 = 1e-5;

    private final float[] weights;
    private final float bias;

    private UrlNgramModel(float[] weights, float bias) {
        this.weights = weights;
        this.bias = bias;
    }

    public static UrlNgramModel train(String[] urls, int[] labels, int epochs, long seed) {
        if (urls.length != labels.length || urls.length < 4) throw new IllegalArgumentException("Training data must contain at least four URL/label pairs.");
        if (epochs < 1 || epochs > 30) throw new IllegalArgumentException("Epoch count must be between 1 and 30.");
        int positives = 0;
        for (int label : labels) {
            if (label != 0 && label != 1) throw new IllegalArgumentException("Labels must be 0 or 1.");
            positives += label;
        }
        if (positives == 0 || positives == labels.length) throw new IllegalArgumentException("Training data must include both classes.");

        float[] weights = new float[DIMENSIONS];
        float bias = 0f;
        double positiveWeight = (double) labels.length / (2 * positives);
        double negativeWeight = (double) labels.length / (2 * (labels.length - positives));
        int[] order = new int[urls.length];
        for (int i = 0; i < order.length; i++) order[i] = i;
        java.util.Random random = new java.util.Random(seed);

        for (int epoch = 0; epoch < epochs; epoch++) {
            for (int i = order.length - 1; i > 0; i--) {
                int j = random.nextInt(i + 1);
                int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
            }
            double learningRate = 0.12 / (1.0 + 0.35 * epoch);
            for (int row : order) {
                Vector vector = vectorize(urls[row]);
                double logit = bias;
                for (int i = 0; i < vector.indices.length; i++) logit += weights[vector.indices[i]] * vector.values[i];
                double probability = sigmoid(logit);
                double classWeight = labels[row] == 1 ? positiveWeight : negativeWeight;
                double error = (probability - labels[row]) * classWeight;
                bias -= (float) (learningRate * error);
                for (int i = 0; i < vector.indices.length; i++) {
                    int index = vector.indices[i];
                    weights[index] -= (float) (learningRate * (error * vector.values[i] + L2 * weights[index]));
                }
            }
        }
        return new UrlNgramModel(weights, bias);
    }

    /** Returns the model's estimated probability that the URL is phishing. */
    public double phishingProbability(String url) {
        Vector vector = vectorize(url);
        double logit = bias;
        for (int i = 0; i < vector.indices.length; i++) logit += weights[vector.indices[i]] * vector.values[i];
        return sigmoid(logit);
    }

    public void save(Path path) throws IOException {
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        try (DataOutputStream out = new DataOutputStream(Files.newOutputStream(path))) {
            out.writeInt(MAGIC);
            out.writeInt(VERSION);
            out.writeInt(DIMENSIONS);
            out.writeFloat(bias);
            for (float weight : weights) out.writeFloat(weight);
        }
    }

    public static UrlNgramModel load(Path path) throws IOException {
        try (DataInputStream in = new DataInputStream(Files.newInputStream(path))) {
            if (in.readInt() != MAGIC) throw new IOException("Unrecognized phishing model file.");
            if (in.readInt() != VERSION) throw new IOException("Unsupported phishing model version.");
            int dimensions = in.readInt();
            if (dimensions != DIMENSIONS) throw new IOException("Unexpected model feature-space size.");
            float bias = in.readFloat();
            float[] weights = new float[dimensions];
            for (int i = 0; i < dimensions; i++) weights[i] = in.readFloat();
            if (in.read() != -1) throw new IOException("Model file contains trailing data.");
            return new UrlNgramModel(weights, bias);
        }
    }

    /** Loads the trained model when present; a missing file is handled by the API fallback. */
    public static UrlNgramModel loadIfPresent() {
        String configured = System.getenv().getOrDefault("PHISHING_MODEL_PATH", "model/url-char-ngram.bin");
        Path path = Path.of(configured);
        if (!Files.isRegularFile(path)) return null;
        try {
            return load(path);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to load phishing model at " + path.toAbsolutePath(), ex);
        }
    }

    private static Vector vectorize(String input) {
        String url = input == null ? "" : input.trim().toLowerCase(Locale.ROOT);
        if (url.length() > MAX_URL_LENGTH) url = url.substring(0, MAX_URL_LENGTH);
        String text = "^" + url + "$";
        int capacity = Math.max(1, (text.length() - 2) + (text.length() - 3) + (text.length() - 4));
        int[] hashes = new int[capacity];
        int size = 0;
        for (int n = 3; n <= 5; n++) {
            for (int start = 0; start + n <= text.length(); start++) {
                int hash = 0x811c9dc5;
                for (int p = start; p < start + n; p++) {
                    hash ^= text.charAt(p);
                    hash *= 0x01000193;
                }
                hashes[size++] = hash & (DIMENSIONS - 1);
            }
        }
        Arrays.sort(hashes, 0, size);
        int unique = 0;
        for (int i = 0; i < size; ) {
            int j = i + 1;
            while (j < size && hashes[j] == hashes[i]) j++;
            hashes[unique++] = hashes[i];
            i = j;
        }
        int[] indices = Arrays.copyOf(hashes, unique);
        float[] values = new float[unique];
        int cursor = 0;
        double squaredNorm = 0;
        for (int i = 0; i < size; ) {
            int j = i + 1;
            while (j < size && hashes[j] == hashes[i]) j++;
            float count = j - i;
            values[cursor++] = count;
            squaredNorm += (double) count * count;
            i = j;
        }
        float norm = (float) Math.sqrt(Math.max(1.0, squaredNorm));
        for (int i = 0; i < values.length; i++) values[i] /= norm;
        return new Vector(indices, values);
    }

    private static double sigmoid(double value) {
        if (value >= 0) {
            double z = Math.exp(-value);
            return 1.0 / (1.0 + z);
        }
        double z = Math.exp(value);
        return z / (1.0 + z);
    }

    private record Vector(int[] indices, float[] values) {}
}
