package br.com.security;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CRUD e cancelamento do ScanManager. Usa IDs unicos por teste para nao
 * colidir no mapa estatico compartilhado.
 */
class ScanManagerTest {

    private String id() {
        return UUID.randomUUID().toString();
    }

    @Test
    void putGetRemove() {
        String id = id();
        ScanStatus s = new ScanStatus(Path.of("/tmp/x"));
        assertNull(ScanManager.get(id));
        ScanManager.put(id, s);
        assertEquals(s, ScanManager.get(id));
        ScanManager.remove(id);
        assertNull(ScanManager.get(id));
    }

    @Test
    void cancelNonexistentReturnsFalse() {
        assertFalse(ScanManager.cancel(id()));
    }

    @Test
    void cancelRunningScanTransitionsToCancelled() {
        String id = id();
        ScanStatus s = new ScanStatus(Path.of("/tmp/nao-existe-" + id));
        s.update(ScanStatus.State.RUNNING, "rodando");
        ScanManager.put(id, s);

        assertTrue(ScanManager.cancel(id));
        assertEquals(ScanStatus.State.CANCELLED, s.getState());
        assertTrue(s.isCancelRequested());
        ScanManager.remove(id);
    }

    @Test
    void cancelAlreadyFinalReturnsTrueWithoutChangingState() {
        String id = id();
        ScanStatus s = new ScanStatus(Path.of("/tmp/x"));
        s.setCompleted(Path.of("/tmp/r.html"));
        ScanManager.put(id, s);

        assertTrue(ScanManager.cancel(id)); // existia, mas ja final
        assertEquals(ScanStatus.State.COMPLETED, s.getState());
        ScanManager.remove(id);
    }
}
