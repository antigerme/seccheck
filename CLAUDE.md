# SecCheck — guia rapido para o agente

Aplicacao web Jakarta EE que executa OWASP Dependency-Check embutido. Upload
de `.jar/.war/.ear`, scan em background com pool de threads, polling de status
e download do relatorio HTML.

## Workflow de PR (regra do dono)

Projeto mantido por uma unica pessoa (`andre@felicio.com.br`). Fluxo padrao:

1. Cada feature/fix em uma branch curta cortada do `main` atualizado.
2. Push -> PR criado pela UI do Claude Code.
3. Aprovacao + **Squash and merge** (sempre — nao usar "Create a merge commit"
   nem "Rebase and merge") + apagar a branch remota.

**Antes de cada squash-merge**, garantir que a branch esta atualizada com o
`main` (botao "Update branch" no PR). Squashes sequenciais de branches stale
ja causaram perda silenciosa de codigo neste repo (ver PR #11).

Quando cortar uma nova branch, sempre baseie em `origin/main` recem-puxado.
Nao reutilize branches locais antigas para features novas.

## Comandos uteis

```bash
mvn clean package          # gera target/ROOT.war (roda os testes)
mvn test                   # so a suite de testes (JUnit 5)
mvn verify                 # compile + test + package (o que o CI roda)
mvn verify -Pself-scan     # alem do acima, escaneia o proprio WAR (precisa NVD)
```

## Testes (`src/test/java/br/com/security/`)

- **Unitarios puros:** `SeverityTest`, `FixSuggesterVersionTest`, `ScanStatusTest`,
  `ScanManagerTest`, `FileUtilsTest`, `ScanCleanupTest`, `SecurityHeadersFilterTest`.
- **Integracao contra a API real do dep-check:** `VulnDetailsIntegrationTest`,
  `FixSuggesterIntegrationTest`, `FindingsAndSeverityIntegrationTest`,
  `CycloneDxBuilderIntegrationTest`. Usam `TestFixtures.evidenceEngine()` —
  Engine em `EVIDENCE_COLLECTION` (sem rede/NVD) + `Dependency`/`Vulnerability`
  sinteticas. Sao eles que pegam quebra silenciosa de reflection (o bug do
  `versionEndExcluding` ficou latente do PR #7 ao #16 por falta deste teste).
- Ao mexer em `VulnDetails`/`FixSuggester`/`CycloneDxBuilder`/`Severity`, **rode
  os testes de integracao** — eles validam a reflection contra o dep-check de
  verdade. CI (`.github/workflows/ci.yml`) roda `mvn verify` em todo PR.

## Estrutura

- `src/main/java/br/com/security/`: codigo Java. Pacote unico.
- `src/main/webapp/`: front-end (HTML/CSS/JS estatico), `WEB-INF/web.xml`,
  paginas de erro em `/error/`.

## Convencoes

- **Logging:** use `LogUtils` (debug/info/warn/error). Por baixo e SLF4J;
  alinha com o motor do dependency-check.
- **JSON:** todas as respostas saem por `JsonResponse.write` /
  `JsonResponse.writeError`. Nunca concatene strings JSON.
- **Detalhe de vulnerabilidade:** extraia via `VulnDetails.from(vuln)` — e a
  UNICA fonte de reflection sobre `Vulnerability` do dep-check. Tanto o SBOM
  (`CycloneDxBuilder`) quanto a API (`FindingsExtractor`/`/api/status`) usam,
  garantindo paridade. Nao recrie reflection ad-hoc sobre `Vulnerability`.
- **Variaveis de ambiente:** leia via `AppContextListener.getEnvInt/getEnvLong`
  para uniformizar parsing e log de erro.
- **Ciclo de vida:** qualquer recurso global novo (executor, scheduler, cache)
  deve ser iniciado em `AppContextListener.contextInitialized` e parado em
  `contextDestroyed`. Nao crie pools dentro de servlets.
- **Validacao de input:** ids sao UUID — sempre `UUID.fromString(id)` antes
  de consultar o `ScanManager`.
- **Limpeza:** ao falhar gravando arquivo de upload, chame
  `FileUtils.deleteDirectoryRecursively(tempDir)`. Em sucesso, o `UploadServlet`
  ja deleta o arquivo enviado logo apos a engine gerar o relatorio. O proprio
  relatorio HTML e removido pelo `ReportServlet` imediatamente apos o download
  bem-sucedido (politica no-re-download). O TTL do `ScanManager` so coleta o
  que sobrar (downloads interrompidos, scans abandonados em ERROR, etc.).
- **Build metadata:** versao/commit/branch entram no MANIFEST.MF via
  `git-commit-id-maven-plugin` e sao lidos por `BuildInfo.load()` no startup.
  Para expor um novo campo: adicione em `<manifestEntries>` no `pom.xml`,
  depois em `putIfPresent` em `BuildInfo.java`.

## Seguranca

- Headers HTTP centralizados em `SecurityHeadersFilter`. CSP endurecida:
  so `'self'`, sem `'unsafe-inline'`, sem origens externas, com `form-action`/
  `base-uri`/`frame-ancestors`. **Nao adicione `style="..."` inline** em HTML/JS
  (quebra com a CSP) — use classes no `style.css`. `SecurityHeadersFilterTest`
  trava regressao nesses headers.
- HSTS esta comentado: ligar somente atras de TLS.
- Sem autenticacao: assume rede interna. Adicione auth antes de expor
  publicamente.

## Pontos a observar ao mudar

- **Pool de scans (`AppContextListener.scanExecutor`)**: cada Engine instancia
  uma conexao H2 ao banco NVD em `DPCK_DATA_DIR`. Em FS lento, mantenha
  `DPCK_THREAD_POOL_SIZE=1`.
- **Locks**: scans usam `DB_LOCK.readLock()`, updates usam `writeLock()`.
  Nunca segure um lock entre threads diferentes.
- **Cancelamento**: `DependencyCheckRunner` checa `status.isCancelRequested()`
  em pontos chave. Engine do OWASP nao tem cancel proprio — o melhor que
  conseguimos e marcar como cancelado e descartar o resultado.
- **Resiliencia NVD**: a API publica do NIST e historicamente instavel
  (503/HTTP2 stream reset). `DependencyCheckRunner.createSettings()` aplica:
  `nvd.api.delay` (env `DPCK_NVD_API_DELAY_MS`, padrao 4000ms) e
  `nvd.api.max.retry.count` (env `DPCK_NVD_MAX_RETRIES`, padrao 10) — bem
  abaixo do default agressivo do dep-check (0ms/30 retries) para reduzir
  ruido no log e dar tempo da API se recuperar. `LogUtils` tambem rebaixa
  `AsyncHttpRequestRetryExec` e `NvdApiRetryStrategy` para WARN em modo
  normal (em `DPCK_DEBUG=debug` voltam ao default).
