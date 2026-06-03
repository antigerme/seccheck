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
        if (!hasAnyConsumable(status)) {
            LogUtils.info("Scan " + scanId + ": todos os formatos foram baixados. Removendo workDir.");
            FileUtils.deleteDirectoryRecursively(status.getWorkDir());
            ScanManager.remove(scanId);
        }
    }

    private static boolean hasAnyConsumable(ScanStatus status) {
        return existsOrNull(status.getReportPath()) || existsOrNull(status.getSbomPath());
    }

    private static boolean existsOrNull(Path p) {
        return p != null && Files.exists(p);
    }
}
