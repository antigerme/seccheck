package br.com.security;

import java.util.List;

/**
 * Snippet de pom.xml gerado automaticamente para corrigir CVEs encontradas
 * numa dependencia. A ideia e que o usuario possa colar diretamente no
 * {@code <dependencies>} do projeto vulneravel — o Maven aplica "nearest wins"
 * e sobrescreve a transitiva problematica, mesmo padrao que aplicamos
 * manualmente em gson/httpclient5-cache neste proprio projeto.
 */
public final class FixSuggestion {

    public final String groupId;
    public final String artifactId;
    public final String currentVersion;
    public final String fixedVersion;
    public final List<String> cves;
    public final Severity.Level severity;
    /** True se ao menos uma das CVEs deste artefato esta na CISA KEV. */
    public final boolean knownExploited;
    public final String pomSnippet;

    public FixSuggestion(String groupId, String artifactId, String currentVersion,
                         String fixedVersion, List<String> cves, Severity.Level severity,
                         boolean knownExploited) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.currentVersion = currentVersion;
        this.fixedVersion = fixedVersion;
        this.cves = List.copyOf(cves);
        this.severity = severity;
        this.knownExploited = knownExploited;
        this.pomSnippet = buildSnippet(groupId, artifactId, fixedVersion, cves);
    }

    private static String buildSnippet(String g, String a, String fixed, List<String> cves) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!-- Fix: ").append(String.join(", ", cves)).append(" -->\n");
        sb.append("<dependency>\n");
        sb.append("    <groupId>").append(g).append("</groupId>\n");
        sb.append("    <artifactId>").append(a).append("</artifactId>\n");
        // Range aberto: garante que o Maven sempre puxe a versao mais recente
        // a partir da primeira que corrige todas as CVEs conhecidas hoje.
        sb.append("    <version>[").append(fixed).append(",)</version>\n");
        sb.append("</dependency>");
        return sb.toString();
    }
}
