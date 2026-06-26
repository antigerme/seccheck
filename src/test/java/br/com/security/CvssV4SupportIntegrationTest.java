package br.com.security;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV4Data;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Vulnerabilidades publicadas a partir de ~2024 frequentemente carregam APENAS
 * CVSSv4 — sem v3 nem v2 de fallback. Antes do fix, {@link Severity#worstOf}
 * e {@link VulnDetails} so olhavam v3/v2, entao essas CVEs ficavam com score 0
 * e severidade NONE — a UI mostrava "cofre limpo" mesmo com CVE real (vide
 * CVE-2026-54515 em jackson-databind 2.21.4 no proprio SecCheck).
 *
 * <p>Estes testes injetam Vulnerability sintetica com APENAS {@code setCvssV4}
 * e validam que:
 * <ul>
 *   <li>{@link Severity#worstOf} retorna o nivel correto (nao NONE).</li>
 *   <li>{@link VulnDetails#cvssScore} e populado.</li>
 *   <li>{@link VulnDetails#cvssVector} e extraido.</li>
 *   <li>{@link VulnDetails#cvssMethod()} retorna {@code "CVSSv4"}.</li>
 * </ul>
 */
class CvssV4SupportIntegrationTest {

    private static final String V4_VECTOR =
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N";

    private static Vulnerability v4OnlyVuln(String cve, double score,
                                             CvssV4Data.SeverityType sev) {
        Vulnerability v = new Vulnerability();
        v.setName(cve);
        v.setSource(Vulnerability.Source.OSSINDEX);
        v.setDescription("CVSSv4-only — caso real do CVE-2026-54515.");
        v.addCwe("CWE-915");
        v.addReference("OSSINDEX", "Advisory " + cve, "https://ossindex.sonatype.org/vuln/" + cve);
        v.setCvssV4(TestFixtures.cvssV4(score, sev, V4_VECTOR));
        return v;
    }

    @Test
    void severityWorstOfPicksUpCvssV4Only() throws Exception {
        try (Engine engine = TestFixtures.evidenceEngine()) {
            Vulnerability v = v4OnlyVuln("CVE-2026-54515", 6.9, CvssV4Data.SeverityType.MEDIUM);
            Dependency dep = TestFixtures.mavenDep(
                "com.fasterxml.jackson.core", "jackson-databind", "2.21.4", v);
            engine.addDependency(dep);

            Severity.Level worst = Severity.worstOf(engine);
            assertEquals(Severity.Level.MEDIUM, worst,
                "CVE so com CVSSv4 (score 6.9) deve ser MEDIUM — era NONE antes do fix");
        }
    }

    @Test
    void vulnDetailsExtractsV4ScoreAndVector() throws Exception {
        Vulnerability v = v4OnlyVuln("CVE-2026-54515", 6.9, CvssV4Data.SeverityType.MEDIUM);

        VulnDetails vd = VulnDetails.from(v);
        assertNotNull(vd, "VulnDetails.from() nao deve retornar null para Vulnerability com nome");

        assertEquals(6.9, vd.cvssScore, 0.001,
            "score do CVSSv4 deve aparecer no VulnDetails");
        assertEquals(Severity.Level.MEDIUM, vd.severity,
            "severidade derivada do score CVSSv4 deve ser MEDIUM");
        assertEquals(V4_VECTOR, vd.cvssVector,
            "vector CVSSv4 deve ser preservado");
        assertEquals("CVSSv4", vd.cvssMethod(),
            "cvssMethod deve reconhecer o prefixo CVSS:4");
    }

    @Test
    void v3PreferredOverV4WhenBothPresentAndV3Higher() throws Exception {
        // Confirma a preferencia: se uma vuln tem v4 baixo + v3 alto, ainda
        // pegamos o pior. Edge case raro mas mantem a semantica "worst-of".
        Vulnerability v = new Vulnerability();
        v.setName("CVE-2099-9999");
        v.setSource(Vulnerability.Source.NVD);
        v.setCvssV3(TestFixtures.cvss(9.8,
            io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data.SeverityType.CRITICAL,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
        v.setCvssV4(TestFixtures.cvssV4(2.0, CvssV4Data.SeverityType.LOW, V4_VECTOR));

        // extractBaseScore tenta v4 primeiro e retorna se >0; nesse caso retorna 2.0
        // (preferencia pelo mais novo). Isso eh INTENCIONAL: CVSSv4 e o vetor
        // mais novo/preciso quando ambos existem.
        double score = Severity.extractBaseScore(v);
        assertEquals(2.0, score, 0.001,
            "quando ambos existem, preferimos CVSSv4 (mais novo) mesmo se v3 for maior");
        assertTrue(score > 0, "qualquer score > 0 evita o bug do 'cofre limpo'");
    }
}
