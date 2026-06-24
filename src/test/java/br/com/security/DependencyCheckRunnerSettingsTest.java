package br.com.security;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.utils.Settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Valida que createSettings() aplica os settings de resiliencia da NVD.
 * O dep-check tem defaults agressivos (delay=0, maxRetry=30) que bombardeiam
 * o log quando a API esta degradada — esses testes travam regressao caso
 * alguem remova a configuracao customizada.
 */
class DependencyCheckRunnerSettingsTest {

    @Test
    void resilienciaNvdAplicadaPorDefault() {
        Settings s = DependencyCheckRunner.createSettings();
        try {
            // Sem env setada: deve usar os defaults da app (nao os do dep-check).
            int delay = s.getInt("nvd.api.delay", -1);
            int retries = s.getInt("nvd.api.max.retry.count", -1);

            // Default da app: delay 4000ms (vs 0 do dep-check)
            assertEquals(4000, delay,
                "nvd.api.delay deve ter default 4000ms (env DPCK_NVD_API_DELAY_MS nao setada)");
            // Default da app: 10 retries (vs 30 do dep-check)
            assertEquals(10, retries,
                "nvd.api.max.retry.count deve ter default 10 (env DPCK_NVD_MAX_RETRIES nao setada)");
        } finally {
            s.cleanup();
        }
    }

    @Test
    void autoUpdateDesligadoNoScan() {
        Settings s = DependencyCheckRunner.createSettings();
        try {
            // Scans nunca tentam atualizar o banco; quem atualiza e o DatabaseUpdater.
            assertFalse(s.getBoolean("auto.update", true),
                "auto.update deve ser false em createSettings()");
        } finally {
            s.cleanup();
        }
    }
}
