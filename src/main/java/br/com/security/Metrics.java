package br.com.security;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Contadores em memoria para observabilidade basica. Os valores sao expostos
 * pelo endpoint /api/metrics e tambem aparecem no /api/health. Nao substituem
 * Micrometer/Prometheus, mas servem para troubleshooting rapido em producao
 * sem trazer dependencias adicionais.
 */
public final class Metrics {

    public static final AtomicLong uploadsAccepted = new AtomicLong();
    public static final AtomicLong uploadsRejected = new AtomicLong();
    public static final AtomicLong scansCompleted = new AtomicLong();
    public static final AtomicLong scansFailed = new AtomicLong();
    public static final AtomicLong scansCancelled = new AtomicLong();
    public static final AtomicLong nvdUpdatesOk = new AtomicLong();
    public static final AtomicLong nvdUpdatesFailed = new AtomicLong();

    /** Timestamp (epoch ms) do ultimo update bem-sucedido. 0 = nunca atualizou. */
    public static final AtomicLong lastNvdUpdateMs = new AtomicLong();

    /** Soma de millis gastos em scans concluidos (para calcular tempo medio). */
    public static final AtomicLong totalScanDurationMs = new AtomicLong();

    private Metrics() {}

    public static long averageScanDurationMs() {
        long completed = scansCompleted.get();
        if (completed == 0) return 0;
        return totalScanDurationMs.get() / completed;
    }
}
