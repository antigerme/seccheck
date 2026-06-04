package br.com.security;

import java.util.List;

/**
 * Uma CVE individual encontrada num scan, ja decorada com a coordenada
 * Maven da dep afetada. Usado pelo Diff Scan (mesma {@code group:artifact:cve}
 * = mesma finding) e exposto pela API /api/status com os mesmos detalhes
 * ricos que vao para o SBOM (paridade SBOM <-> API via {@link VulnDetails}).
 */
public final class ScanFinding {

    public final String groupId;
    public final String artifactId;
    public final String version;
    public final VulnDetails vuln;

    public ScanFinding(String groupId, String artifactId, String version, VulnDetails vuln) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
        this.vuln = vuln;
    }

    // Atalhos usados pelo codigo existente (Diff Scan / logs)
    public String cveName() { return vuln.cveName; }
    public Severity.Level severity() { return vuln.severity; }
    public double cvssScore() { return vuln.cvssScore; }
    public List<Integer> cwes() { return vuln.cwes; }
}
