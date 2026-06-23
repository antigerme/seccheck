package br.com.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Politica de limpeza pos-download, com foco no race condition do resumo
 * executivo: baixar todos os formatos NAO pode remover o scan do ScanManager
 * enquanto o resumo (Claude API) ainda esta sendo gerado — senao /api/summary
 * daria 404 e o resumo (ja pago) seria perdido.
 */
class ScanCleanupTest {

    @Test
    void keepsScanWhileSummaryPending(@TempDir Path workDir) {
        String id = UUID.randomUUID().toString();
        ScanStatus status = new ScanStatus(workDir);
        status.setCompleted(null);                 // sem report/sbom -> nada consumivel
        status.setSummaryState(ScanStatus.SummaryState.GENERATING);
        ScanManager.put(id, status);

        // Todos os "formatos" baixados (nenhum existe) com resumo em geracao:
        ScanCleanup.afterFileConsumed(id, status, null);

        assertNotNull(ScanManager.get(id),
            "scan deve permanecer no mapa enquanto o resumo nao termina");

        // Resumo conclui -> proxima limpeza remove o scan
        status.setExecutiveSummary("- pronto");
        ScanCleanup.afterFileConsumed(id, status, null);
        assertNull(ScanManager.get(id), "apos resumo READY o scan e coletado");
    }

    @Test
    void removesScanImmediatelyWhenSummaryDisabled(@TempDir Path workDir) {
        String id = UUID.randomUUID().toString();
        ScanStatus status = new ScanStatus(workDir);
        status.setCompleted(null);
        // summaryState default = DISABLED (sem ANTHROPIC_API_KEY)
        ScanManager.put(id, status);

        ScanCleanup.afterFileConsumed(id, status, null);
        assertNull(ScanManager.get(id),
            "sem resumo, o scan e removido assim que os formatos sao consumidos");
    }
}
