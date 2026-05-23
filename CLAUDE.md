# SecCheck — guia rapido para o agente

Aplicacao web Jakarta EE que executa OWASP Dependency-Check embutido. Upload
de `.jar/.war/.ear`, scan em background com pool de threads, polling de status
e download do relatorio HTML.

## Comandos uteis

```bash
mvn clean package          # gera target/ROOT.war
mvn verify -Pself-scan     # roda o dependency-check-maven contra o proprio WAR
```

Nao ha testes automatizados ainda. Ao tocar logica de negocio, descreva no PR
o que foi validado manualmente.

## Estrutura

- `src/main/java/br/com/security/`: codigo Java. Pacote unico.
- `src/main/webapp/`: front-end (HTML/CSS/JS estatico), `WEB-INF/web.xml`,
  paginas de erro em `/error/`.

## Convencoes

- **Logging:** use `LogUtils` (debug/info/warn/error). Por baixo e SLF4J;
  alinha com o motor do dependency-check.
- **JSON:** todas as respostas saem por `JsonResponse.write` /
  `JsonResponse.writeError`. Nunca concatene strings JSON.
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

- Headers HTTP centralizados em `SecurityHeadersFilter`. CSP atual permite
  Google Fonts mas a UI ja usa stack de fontes do sistema; e seguro remover
  esses hosts da CSP no futuro.
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
