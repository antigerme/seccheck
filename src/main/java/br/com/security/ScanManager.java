package br.com.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Registro central das varreduras em execucao. Continua estatico para manter
 * a API simples nos servlets, mas a inicializacao do cleaner agora e
 * controlada pelo AppContextListener (via {@link #startCleaner()}) e a
 * derrubada por {@link #shutdown()}, evitando vazamento de thread quando o
 * WAR e parado/redeployado.
 */
public class ScanManager {

    private static final ConcurrentHashMap<String, ScanStatus> scans = new ConcurrentHashMap<>();

    private static final long TTL_FINISHED_MS = getEnvLong("DPCK_SCAN_TTL_MINUTES", 120) * 60 * 1000;
    private static final long TTL_STUCK_MS = getEnvLong("DPCK_SCAN_STUCK_MINUTES", 240) * 60 * 1000;

    private static volatile ScheduledExecutorService cleaner;

    public static synchronized void startCleaner() {
        if (cleaner != null) return;
        cleaner = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "dpck-scan-cleaner");
            t.setDaemon(true);
            return t;
        });
        cleaner.scheduleAtFixedRate(ScanManager::cleanExpiredScans, 15, 15, TimeUnit.MINUTES);
        LogUtils.info("ScanManager cleaner iniciado (TTL concluidos: " + (TTL_FINISHED_MS / 60000) +
            " min, TTL travados: " + (TTL_STUCK_MS / 60000) + " min)");
    }

    public static synchronized void shutdown() {
        if (cleaner == null) return;
        cleaner.shutdownNow();
        cleaner = null;
    }

    public static void put(String id, ScanStatus status) {
        scans.put(id, status);
    }

    public static ScanStatus get(String id) {
        return scans.get(id);
    }

    public static void remove(String id) {
        scans.remove(id);
    }

    public static int activeCount() {
        return scans.size();
    }

    public static Map<String, ScanStatus> snapshot() {
        return Map.copyOf(scans);
    }

    /**
     * Sinaliza cancelamento, interrompe a task se possivel e remove o scan da
     * memoria. Retorna true se o scan existia (mesmo que ja estivesse em
     * estado final).
     */
    public static boolean cancel(String id) {
        ScanStatus status = scans.get(id);
        if (status == null) return false;

        synchronized (status) {
            if (status.isFinal()) {
                return true;
            }
            status.requestCancel();
            if (status.getTask() != null) {
                status.getTask().cancel(true);
            }
            status.setCancelled();
        }

        if (status.getWorkDir() != null) {
            FileUtils.deleteDirectoryRecursively(status.getWorkDir());
        }
        Metrics.scansCancelled.incrementAndGet();
        return true;
    }

    /**
     * Remove scans expirados da memoria e limpa seus diretorios temporarios.
     * - COMPLETED/ERROR/CANCELLED: expira apos TTL_FINISHED_MS (padrao 2h)
     * - RUNNING travado: expira apos TTL_STUCK_MS (padrao 4h)
     * - QUEUED: mesma regra de RUNNING
     */
    static void cleanExpiredScans() {
        long now = System.currentTimeMillis();
        int removed = 0;

        for (var entry : scans.entrySet()) {
            String id = entry.getKey();
            ScanStatus status = entry.getValue();
            long age = now - status.getCreatedAt();

            boolean expired = false;
            ScanStatus.State state = status.getState();

            if (status.isFinal() && age > TTL_FINISHED_MS) {
                expired = true;
            } else if ((state == ScanStatus.State.RUNNING || state == ScanStatus.State.QUEUED)
                    && age > TTL_STUCK_MS) {
                expired = true;
                LogUtils.warn("Scan " + id + " em estado " + state + " ha mais de " +
                    (TTL_STUCK_MS / 60000) + " min. Considerando travado e removendo.");
            }

            if (expired) {
                if (status.getWorkDir() != null) {
                    FileUtils.deleteDirectoryRecursively(status.getWorkDir());
                }
                scans.remove(id);
                removed++;
                LogUtils.info("Scan expirado removido: " + id + " (estado: " + state +
                    ", idade: " + (age / 60000) + " min)");
            }
        }

        if (removed > 0) {
            LogUtils.info("Limpeza automatica concluida: " + removed + " scan(s) expirado(s). " +
                "Ativos restantes: " + scans.size());
        }
    }

    private static long getEnvLong(String name, long defaultValue) {
        String val = System.getenv(name);
        if (val != null && !val.isBlank()) {
            try {
                return Long.parseLong(val.trim());
            } catch (NumberFormatException e) {
                // ignora e usa padrao
            }
        }
        return defaultValue;
    }
}
