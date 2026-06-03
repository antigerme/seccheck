package br.com.security;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Metricas em memoria para diagnostico rapido. Nao substitui Prometheus.
 * Formato JSON para evitar parsers customizados em ferramentas internas.
 */
@WebServlet(name = "MetricsServlet", urlPatterns = {"/api/metrics"})
public class MetricsServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        ObjectNode body = JsonResponse.node();
        ObjectNode uploads = body.putObject("uploads");
        uploads.put("accepted", Metrics.uploadsAccepted.get());
        uploads.put("rejected", Metrics.uploadsRejected.get());

        ObjectNode scans = body.putObject("scans");
        scans.put("completed", Metrics.scansCompleted.get());
        scans.put("failed", Metrics.scansFailed.get());
        scans.put("cancelled", Metrics.scansCancelled.get());
        scans.put("active", ScanManager.activeCount());
        scans.put("avgDurationMs", Metrics.averageScanDurationMs());

        ObjectNode summary = body.putObject("executiveSummary");
        summary.put("enabled", ExecutiveSummaryService.isEnabled());
        summary.put("generated", Metrics.summariesGenerated.get());
        summary.put("failed", Metrics.summariesFailed.get());

        ObjectNode nvd = body.putObject("nvd");
        nvd.put("updatesOk", Metrics.nvdUpdatesOk.get());
        nvd.put("updatesFailed", Metrics.nvdUpdatesFailed.get());
        nvd.put("lastUpdateMs", Metrics.lastNvdUpdateMs.get());

        ObjectNode pool = body.putObject("pool");
        pool.put("size", AppContextListener.poolSize());
        pool.put("queueSize", AppContextListener.queueSize());
        pool.put("queueCapacity", AppContextListener.queueCapacity());

        ObjectNode runtime = body.putObject("runtime");
        Runtime rt = Runtime.getRuntime();
        runtime.put("heapUsedMb", (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024));
        runtime.put("heapMaxMb", rt.maxMemory() / (1024 * 1024));
        runtime.put("processors", rt.availableProcessors());

        JsonResponse.write(response, HttpServletResponse.SC_OK, body);
    }
}
