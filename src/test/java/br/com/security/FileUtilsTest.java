package br.com.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileUtilsTest {

    @Test
    void isZipMagicTrueForRealZipHeader(@TempDir Path dir) throws Exception {
        // PK\x03\x04 — header local de arquivo ZIP/JAR/WAR/EAR
        Path f = dir.resolve("a.jar");
        Files.write(f, new byte[]{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00});
        assertTrue(FileUtils.isZipMagic(f));
    }

    @Test
    void isZipMagicTrueForEmptyArchiveHeader(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("empty.jar");
        Files.write(f, new byte[]{0x50, 0x4B, 0x05, 0x06});
        assertTrue(FileUtils.isZipMagic(f));
    }

    @Test
    void isZipMagicFalseForNonZip(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("fake.jar");
        Files.writeString(f, "isto nao e um zip de jeito nenhum");
        assertFalse(FileUtils.isZipMagic(f));
    }

    @Test
    void isZipMagicFalseForTooShort(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("short.jar");
        Files.write(f, new byte[]{0x50, 0x4B});
        assertFalse(FileUtils.isZipMagic(f));
    }

    @Test
    void deleteDirectoryRecursivelyRemovesNestedTree(@TempDir Path dir) throws Exception {
        Path nested = dir.resolve("a/b/c");
        Files.createDirectories(nested);
        Files.writeString(nested.resolve("file.txt"), "x");
        Files.writeString(dir.resolve("a/top.txt"), "y");

        Path target = dir.resolve("a");
        FileUtils.deleteDirectoryRecursively(target);
        assertFalse(Files.exists(target));
    }

    @Test
    void deleteDirectoryRecursivelyNullAndMissingAreSafe(@TempDir Path dir) {
        // Nao deve lancar.
        FileUtils.deleteDirectoryRecursively((Path) null);
        FileUtils.deleteDirectoryRecursively(dir.resolve("nao-existe"));
    }
}
