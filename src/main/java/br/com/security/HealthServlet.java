package br.com.security;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.File;
import java.io.IOException;

/**
 * Endpoint para liveness/readiness probes (Kubernetes, JBoss self-test, LB).
 * Responde 200 quando saudavel; 503 quando ha sintomas de degradacao
 * (banco NVD nunca atualizou, fila completamente cheia).
 */
@WebServlet(name = "HealthServlet", urlPatterns = {"/api/health"})
public class HealthServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        ObjectNode body = JsonResponse.node();

        long lastUpdate = Metrics.lastNvdUpdateMs.get();
        boolean nvdReady = lastUpdate > 0 || hasExistingDataDir();
        boolean queueAvailable = !AppContextListener.isQueueFull();

        boolean healthy = nvdReady && queueAvailable;

        body.put("status", healthy ? "UP" : "DEGRADED");
        body.put("nvdReady", nvdReady);
        body.put("queueAvailable", queueAvailable);
        body.put("activeScans", ScanManager.activeCount());
        body.put("queueSize", AppContextListener.queueSize());
        body.put("queueCapacity", AppContextListener.queueCapacity());
        body.put("poolSize", AppContextListener.poolSize());
        body.put("lastNvdUpdateMs", lastUpdate);

        // Em probes Kubernetes, usar status code permite acoes automaticas.
        // Mantemos 200 mesmo em "DEGRADED" para nao reiniciar o pod
        // enquanto o primeiro update do NVD nao termina — esse pode levar horas.
        // Forneca uma flag explicita pra quem precisar de strict readiness.
        boolean strict = "true".equalsIgnoreCase(request.getParameter("strict"));
        int statusCode = (strict && !healthy) ? HttpServletResponse.SC_SERVICE_UNAVAILABLE : HttpServletResponse.SC_OK;

        JsonResponse.write(response, statusCode, body);
    }

    private boolean hasExistingDataDir() {
        String dataDir = System.getenv("DPCK_DATA_DIR");
        if (dataDir == null || dataDir.isBlank()) {
            dataDir = System.getProperty("user.home") + "/.dependency-check/data";
        }
        File f = new File(dataDir);
        File[] entries = f.listFiles();
        return entries != null && entries.length > 0;
    }
}
