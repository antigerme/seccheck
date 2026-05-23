package br.com.security;

import java.io.File;

public class FileUtils {

    /**
     * Remove um diretorio e todo o seu conteudo recursivamente.
     * Seguro para chamadas com null ou diretorios inexistentes.
     */
    public static void deleteDirectoryRecursively(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] contents = dir.listFiles();
        if (contents != null) {
            for (File f : contents) {
                deleteDirectoryRecursively(f);
            }
        }
        if (!dir.delete()) {
            LogUtils.debug("Falha ao deletar: " + dir.getAbsolutePath());
        }
    }
}
