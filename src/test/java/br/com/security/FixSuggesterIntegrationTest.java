package br.com.security;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Teste de regressao do FixSuggester contra a Engine real.
 *
 * Este teste pega EXATAMENTE o bug que ficou latente do PR #7 ao #16:
 * extractVersionEndExcluding tratava getMatchedVulnerableSoftware() (singular)
 * como Collection, sempre retornava null, e NENHUM scan gerava sugestao de fix.
 */
class FixSuggesterIntegrationTest {

    @Test
    void suggestsFixWithVersionAndAggregatesKev() throws Exception {
        try (Engine engine = TestFixtures.evidenceEngine()) {
            // Mesmo artefato, 2 CVEs: uma KEV (Log4Shell), outra nao.
            Vulnerability kev = TestFixtures.richVuln(
                "CVE-2021-44228", 10.0, CvssV3Data.SeverityType.CRITICAL, "2.17.0", true);
            Vulnerability plain = TestFixtures.richVuln(
                "CVE-2021-45046", 9.0, CvssV3Data.SeverityType.CRITICAL, "2.16.0", false);
            engine.addDependency(TestFixtures.mavenDep(
                "org.apache.logging.log4j", "log4j-core", "2.14.1", kev, plain));

            List<FixSuggestion> fixes = FixSuggester.suggest(engine);

            assertEquals(1, fixes.size(), "deve agrupar as 2 CVEs do mesmo artefato em 1 sugestao");
            FixSuggestion fs = fixes.get(0);
            assertEquals("org.apache.logging.log4j", fs.groupId);
            assertEquals("log4j-core", fs.artifactId);
            assertEquals("2.14.1", fs.currentVersion);
            // Maior versionEndExcluding entre as CVEs vence (2.17.0 > 2.16.0)
            assertEquals("2.17.0", fs.fixedVersion);
            assertEquals(2, fs.cves.size());
            assertEquals(Severity.Level.CRITICAL, fs.severity);
            assertTrue(fs.knownExploited, "basta 1 CVE KEV para marcar o artefato");
            // Snippet pom paste-ready com range aberto na versao de fix
            assertTrue(fs.pomSnippet.contains("log4j-core"));
            assertTrue(fs.pomSnippet.contains("[2.17.0,)"));
        }
    }

    @Test
    void noFixWhenNoVersionEndExcluding() throws Exception {
        try (Engine engine = TestFixtures.evidenceEngine()) {
            // CVE sem versao de fix conhecida -> nao gera sugestao (so o relatorio mostra)
            Vulnerability v = TestFixtures.richVuln(
                "CVE-2099-0001", 7.5, CvssV3Data.SeverityType.HIGH, null, false);
            engine.addDependency(TestFixtures.mavenDep("g", "a", "1.0.0", v));

            assertTrue(FixSuggester.suggest(engine).isEmpty());
        }
    }

    @Test
    void noFixForDependencyWithoutVulnerabilities() throws Exception {
        try (Engine engine = TestFixtures.evidenceEngine()) {
            engine.addDependency(TestFixtures.mavenDep("g", "clean", "1.0.0"));
            assertTrue(FixSuggester.suggest(engine).isEmpty());
        }
    }

    @Test
    void nonMavenDependencyIsSkipped() throws Exception {
        try (Engine engine = TestFixtures.evidenceEngine()) {
            // Dependency sem purl Maven (so um arquivo) — nao deve gerar sugestao.
            Dependency d = new Dependency(new java.io.File("mystery.bin"), true);
            d.addVulnerability(TestFixtures.richVuln(
                "CVE-2099-9", 8.0, CvssV3Data.SeverityType.HIGH, "2.0.0", false));
            engine.addDependency(d);
            assertFalse(FixSuggester.suggest(engine).stream().findAny().isPresent());
        }
    }
}
