package br.com.security;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class ScanManager {
    // Armazena em memoria o status de cada varredura pela chave UUID
    private static final ConcurrentHashMap<String, ScanStatus> scans = new ConcurrentHashMap<>();

    // TTL padrao: 2 horas para scans concluidos/erro, 4 horas para scans travados em RUNNING
    private static final long TTL_FINISHED_MS = getEnvLong("DPCK_SCAN_TTL_MINUTES", 120) * 60 * 1000;
    private static final long TTL_STUCK_MS = getEnvLong("DPCK_SCAN_STUCK_MINUTES", 240) * 60 * 1000;

    private static final ScheduledExecutorService cleaner = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "dpck-scan-cleaner");
        t.setDaemon(true);
        return t;
    });

    static {
        // A cada 15 minutos, verifica e remove scans expirados
        cleaner.scheduleAtFixedRate(ScanManager::cleanExpiredScans, 15, 15, TimeUnit.MINUTES);
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

    /**
     * Remove scans expirados da memoria e limpa seus diretorios temporarios do disco.
     * - COMPLETED/ERROR: expira apos TTL_FINISHED_MS (padrao 2h)
     * - RUNNING travado: expira apos TTL_STUCK_MS (padrao 4h) como rede de seguranca
     * - QUEUED: mesma regra de RUNNING (caso fique na fila indefinidamente)
     */
    private static void cleanExpiredScans() {
        long now = System.currentTimeMillis();
        int removed = 0;

        for (var entry : scans.entrySet()) {
            String id = entry.getKey();
            ScanStatus status = entry.getValue();
            long age = now - status.getCreatedAt();

            boolean expired = false;
            ScanStatus.State state = status.getState();

            if ((state == ScanStatus.State.COMPLETED || state == ScanStatus.State.ERROR)
                    && age > TTL_FINISHED_MS) {
                expired = true;
            } else if ((state == ScanStatus.State.RUNNING || state == ScanStatus.State.QUEUED)
                    && age > TTL_STUCK_MS) {
                expired = true;
                LogUtils.info("Scan " + id + " em estado " + state + " ha mais de " +
                    (TTL_STUCK_MS / 60000) + " min. Considerando travado e removendo.");
            }

            if (expired) {
                // Limpar diretorio temporario do disco
                if (status.getWorkDir() != null) {
                    FileUtils.deleteDirectoryRecursively(status.getWorkDir().toFile());
                }
                scans.remove(id);
                removed++;
                LogUtils.info("Scan expirado removido: " + id + " (estado: " + state +
                    ", idade: " + (age / 60000) + " min)");
            }
        }

        if (removed > 0) {
            LogUtils.info("Limpeza automatica concluida: " + removed + " scan(s) expirado(s) removido(s). " +
                "Scans ativos restantes: " + scans.size());
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
