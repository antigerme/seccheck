package br.com.security;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Politica de limpeza dos artefatos do scan, agora que ha mais de um formato
 * de saida (HTML + SBOM CycloneDX). Cada servlet de download deleta apenas
 * o seu proprio arquivo; quando nenhum dos formatos consumivel sobrou, o
 * workDir inteiro e descartado e o scan e removido do {@link ScanManager}.
 * Assim mantemos a politica "no re-download" por formato, mas permitimos
 * baixar HTML e SBOM separadamente (sem inviabilizar o segundo).
 *
 * O TTL do {@code ScanManager} continua como rede de seguranca para scans
 * abandonados (nenhum formato baixado).
 */
public final class ScanCleanup {

    private ScanCleanup() {}

    public static void afterFileConsumed(String scanId, ScanStatus status, Path consumed) {
        if (consumed != null) {
            try {
                Files.deleteIfExists(consumed);
            } catch (Exception e) {
                LogUtils.warn("Falha ao remover " + consumed + ": " + e.getMessage());
            }
        }
        if (hasAnyConsumable(status)) {
            return; // ainda ha HTML ou SBOM pra baixar
        }

        // Nenhum arquivo pra baixar: o workDir pode ir embora — o resumo executivo
        // trabalha sobre dados em memoria (severity/count/fixSuggestions), nao
        // sobre arquivos. Mas so removemos o scan do ScanManager se o resumo nao
        // estiver pendente; senao /api/summary daria 404 e perderiamos um resumo
        // que ja pode ter sido pago a Claude API. O TTL do ScanManager coleta o
        // scan depois, como rede de seguranca.
        LogUtils.info("Scan " + scanId + ": todos os formatos foram baixados. Removendo workDir.");
        FileUtils.deleteDirectoryRecursively(status.getWorkDir());

        if (status.isSummaryPending()) {
            LogUtils.info("Scan " + scanId + ": mantendo no ScanManager — resumo executivo ainda em geracao.");
            return;
        }
        ScanManager.remove(scanId);
    }

    private static boolean hasAnyConsumable(ScanStatus status) {
        return existsOrNull(status.getReportPath()) || existsOrNull(status.getSbomPath());
    }

    private static boolean existsOrNull(Path p) {
        return p != null && Files.exists(p);
    }
}
