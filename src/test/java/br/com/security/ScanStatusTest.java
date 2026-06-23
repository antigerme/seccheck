package br.com.security;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Maquina de estados do ScanStatus + estado do resumo executivo. */
class ScanStatusTest {

    private ScanStatus newStatus() {
        return new ScanStatus(Path.of("/tmp/whatever"));
    }

    @Test
    void startsQueuedWithDefaults() {
        ScanStatus s = newStatus();
        assertEquals(ScanStatus.State.QUEUED, s.getState());
        assertEquals(0, s.getProgress());
        assertEquals("pt-BR", s.getLangCode());
        assertEquals(ScanStatus.SummaryState.DISABLED, s.getSummaryState());
        assertFalse(s.isFinal());
    }

    @Test
    void completedIsFinalAndCapsProgress() {
        ScanStatus s = newStatus();
        s.update(ScanStatus.State.RUNNING, "rodando");
        s.setCompleted(Path.of("/tmp/r.html"));
        assertEquals(ScanStatus.State.COMPLETED, s.getState());
        assertEquals(100, s.getProgress());
        assertTrue(s.isFinal());
    }

    @Test
    void updateProgressNeverExceeds100() {
        ScanStatus s = newStatus();
        s.updateProgress(150, "msg");
        assertEquals(100, s.getProgress());
    }

    @Test
    void cancelledIsTerminalAndIgnoresLaterUpdates() {
        ScanStatus s = newStatus();
        s.setCancelled();
        assertEquals(ScanStatus.State.CANCELLED, s.getState());
        assertTrue(s.isFinal());
        // Apos cancelado, updates nao podem "ressuscitar" o scan.
        s.update(ScanStatus.State.RUNNING, "tentando voltar");
        assertEquals(ScanStatus.State.CANCELLED, s.getState());
        s.updateProgress(50, "x");
        assertEquals(ScanStatus.State.CANCELLED, s.getState());
    }

    @Test
    void scanResultStored() {
        ScanStatus s = newStatus();
        s.setScanResult(Severity.Level.HIGH, 7, List.of(), List.of());
        assertEquals(Severity.Level.HIGH, s.getSeverity());
        assertEquals(7, s.getVulnerabilityCount());
    }

    @Test
    void executiveSummaryLifecycle() {
        ScanStatus s = newStatus();
        s.setSummaryState(ScanStatus.SummaryState.GENERATING);
        assertEquals(ScanStatus.SummaryState.GENERATING, s.getSummaryState());
        s.setExecutiveSummary("- resumo");
        assertEquals(ScanStatus.SummaryState.READY, s.getSummaryState());
        assertEquals("- resumo", s.getExecutiveSummary());
        assertTrue(s.getSummaryGeneratedAt() > 0);
    }

    @Test
    void cancelRequestFlag() {
        ScanStatus s = newStatus();
        assertFalse(s.isCancelRequested());
        s.requestCancel();
        assertTrue(s.isCancelRequested());
    }
}
