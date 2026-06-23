package br.com.security;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Settings;
import us.springett.parsers.cpe.values.Part;

import java.io.File;

/**
 * Fabrica de objetos do dependency-check para os testes de integracao.
 *
 * Os testes que consomem isto rodam a Engine em {@link Engine.Mode#EVIDENCE_COLLECTION}
 * (sem rede, sem banco NVD) e injetam {@link Dependency}/{@link Vulnerability}
 * sinteticas. Assim exercitamos a reflection real de VulnDetails/FixSuggester/
 * CycloneDxBuilder contra as classes verdadeiras do dep-check — que e onde ja
 * apareceram bugs silenciosos (versionEndExcluding tratado como Collection,
 * "CYCLONEDX" como Format inexistente).
 */
final class TestFixtures {

    private TestFixtures() {}

    /** Engine sem rede/NVD, segura para testes. Lembre de fechar (try-with-resources). */
    static Engine evidenceEngine() throws Exception {
        Settings settings = new Settings();
        settings.setBoolean("autoupdate", false);
        settings.setBoolean("analyzer.ossindex.enabled", false);
        return new Engine(Engine.Mode.EVIDENCE_COLLECTION, settings);
    }

    /** CvssV3 3.1 com score/severity/vector dados. */
    static CvssV3 cvss(double score, CvssV3Data.SeverityType sev, String vector) {
        CvssV3Data data = new CvssV3Data(CvssV3Data.Version._3_1, vector,
            Double.valueOf(score), sev);
        return new CvssV3("NVD", CvssV3.Type.PRIMARY, data);
    }

    /**
     * Vulnerability rica: nome, source, description, 2 CWEs, 1 reference,
     * CVSS 3.1, versao de fix (versionEndExcluding) e flag KEV opcional.
     */
    static Vulnerability richVuln(String cve, double score, CvssV3Data.SeverityType sev,
                                  String fixedVersion, boolean kev) throws Exception {
        Vulnerability v = new Vulnerability();
        v.setName(cve);
        v.setSource(Vulnerability.Source.NVD);
        v.setDescription("Descricao de teste para " + cve);
        v.addCwe("CWE-502");
        v.addCwe("CWE-917");
        v.addReference("NVD", "Advisory " + cve, "https://nvd.nist.gov/vuln/detail/" + cve);
        v.setCvssV3(cvss(score, sev, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"));
        if (fixedVersion != null) {
            VulnerableSoftware vs = new VulnerableSoftwareBuilder()
                .part(Part.APPLICATION).vendor("acme").product("widget").version("1.0.0")
                .versionEndExcluding(fixedVersion).build();
            v.addVulnerableSoftware(vs);
            v.setMatchedVulnerableSoftware(vs);
        }
        if (kev) {
            v.setKnownExploitedVulnerability(
                new org.owasp.dependencycheck.data.knownexploited.json.Vulnerability());
        }
        return v;
    }

    /** Dependency Maven com purl + as vulnerabilidades dadas. */
    static Dependency mavenDep(String group, String artifact, String version,
                               Vulnerability... vulns) throws Exception {
        Dependency d = new Dependency(new File(artifact + "-" + version + ".jar"), true);
        d.addSoftwareIdentifier(new PurlIdentifier("maven", group, artifact, version, Confidence.HIGHEST));
        for (Vulnerability v : vulns) d.addVulnerability(v);
        return d;
    }
}
