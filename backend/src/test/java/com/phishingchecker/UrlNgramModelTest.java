package com.phishingchecker;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UrlNgramModelTest {
    @TempDir Path temp;

    @Test void learnsDistinctUrlPatternsAndCanBeReloaded() throws Exception {
        String[] urls = new String[40];
        int[] labels = new int[40];
        for (int i = 0; i < 20; i++) {
            urls[i] = "https://www.example" + i + ".com/about/products";
            labels[i] = 0;
            urls[i + 20] = "http://verify-account-" + i + ".bad-domain.test/login";
            labels[i + 20] = 1;
        }

        UrlNgramModel model = UrlNgramModel.train(urls, labels, 12, 42);
        double legitimate = model.phishingProbability("https://www.example7.com/about/products");
        double phishing = model.phishingProbability("http://verify-account-9.bad-domain.test/login");
        assertTrue(phishing > legitimate);
        assertTrue(phishing >= 0 && phishing <= 1);

        Path artifact = temp.resolve("model.bin");
        model.save(artifact);
        UrlNgramModel loaded = UrlNgramModel.load(artifact);
        assertEquals(phishing, loaded.phishingProbability("http://verify-account-9.bad-domain.test/login"), 1e-7);
    }

    @Test void rejectsTrainingDataWithOnlyOneClass() {
        assertThrows(IllegalArgumentException.class,
                () -> UrlNgramModel.train(new String[]{"https://one.test", "https://two.test"}, new int[]{0, 0}, 2, 1));
    }
}
