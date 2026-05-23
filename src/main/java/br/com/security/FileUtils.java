package br.com.security;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;

public final class FileUtils {

    private FileUtils() {}

    /**
     * Remove um diretorio recursivamente usando NIO.
     * Trata symlinks de forma segura (nao segue) e e tolerante a falhas
     * em arquivos individuais (loga em debug e continua).
     */
    public static void deleteDirectoryRecursively(Path dir) {
        if (dir == null) return;
        if (!Files.exists(dir)) return;
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    tryDelete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    LogUtils.debug("Visita falhou em " + file + ": " + exc);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                    tryDelete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            LogUtils.debug("Falha ao percorrer " + dir + ": " + e);
        }
    }

    /** Overload de conveniencia para callers que ainda usam File. */
    public static void deleteDirectoryRecursively(File dir) {
        if (dir == null) return;
        deleteDirectoryRecursively(dir.toPath());
    }

    private static void tryDelete(Path p) {
        try {
            Files.deleteIfExists(p);
        } catch (IOException e) {
            LogUtils.debug("Falha ao deletar " + p + ": " + e);
        }
    }

    /**
     * Verifica se o arquivo comeca com os magic bytes de um ZIP/JAR/WAR/EAR
     * (50 4B 03 04 = "PK\x03\x04"). Tambem aceita o sinalizador de arquivo
     * vazio (50 4B 05 06) e o de arquivo "spanned" (50 4B 07 08), embora os
     * dois ultimos sejam raros em JAR/WAR/EAR validos.
     */
    public static boolean isZipMagic(Path file) {
        try (var in = Files.newInputStream(file)) {
            byte[] header = new byte[4];
            int read = in.read(header);
            if (read < 4) return false;
            int b0 = header[0] & 0xFF;
            int b1 = header[1] & 0xFF;
            int b2 = header[2] & 0xFF;
            int b3 = header[3] & 0xFF;
            if (b0 != 0x50 || b1 != 0x4B) return false;
            return (b2 == 0x03 && b3 == 0x04)
                || (b2 == 0x05 && b3 == 0x06)
                || (b2 == 0x07 && b3 == 0x08);
        } catch (IOException e) {
            LogUtils.debug("Falha ao ler magic bytes de " + file + ": " + e);
            return false;
        }
    }
}
