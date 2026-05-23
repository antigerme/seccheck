# SecCheck - Scanner de Vulnerabilidades NVD/OSS (OWASP Dependency-Check)

O **SecCheck** é uma aplicação corporativa robusta construída para auxiliar equipes de Segurança da Informação. A aplicação permite que usuários façam o upload de arquivos `.jar` ou `.war` via interface web e automaticamente roda o motor do **OWASP Dependency-Check Core** de forma embarcada e concorrente, exibindo o status de progresso ao vivo na tela e disponibilizando o relatório final (HTML) para download.

---

## 🚀 Principais Funcionalidades

- **100% Self-Contained:** O motor do OWASP Dependency-Check (`dependency-check-core`) está embutido no projeto. Não é necessário instalar nenhuma ferramenta de linha de comando no servidor JBoss/Tomcat.
- **Interface Web "Glassmorphism":** Design moderno com modo escuro, animações suaves e arrastar/soltar (Drag-and-Drop). Fontes carregadas do próprio sistema (zero CDN externo, funciona offline).
- **Alta Concorrência e Proteção de Memória:** Pool de threads de tamanho fixo (configurável via `DPCK_THREAD_POOL_SIZE`) para processar a fila de arquivos, evitando *crashes* por `OutOfMemory`.
- **Bootstrap Automático do NVD:** Ao iniciar com `DPCK_DATA_DIR` vazio, a aplicação roda um update inicial em background para garantir que o primeiro scan não falhe.
- **Atualização Inteligente do NVD:** O banco de dados do NVD é mantido localmente. Um agendador em segundo plano atualiza silenciosamente os novos CVEs a cada **4 horas** (intervalo configurável).
- **Acompanhamento em Tempo Real:** O front-end faz polling com *backoff* exponencial em caso de falha de rede e mostra exatamente o estado (`Fila`, `Analisando dependências...`, `Concluído`).
- **Cancelamento de Varredura:** O usuário pode interromper um scan a qualquer momento via `POST /api/cancel`.
- **Validação de Tipo Robusta:** Além da extensão, validamos os *magic bytes* ZIP (`50 4B`) para rejeitar arquivos renomeados.
- **Endpoints Operacionais:** `/api/health` (liveness/readiness) e `/api/metrics` (contadores de uploads, scans, NVD, heap) prontos para Kubernetes/JBoss self-test.
- **Segurança de Thread (Locks):** Utilização de `ReentrantReadWriteLock`. Inúmeras análises podem ser feitas paralelamente (Read Lock). A fila só pausa por alguns segundos durante as janelas em que ocorre a escrita (Write Lock) para atualizar as bases do NVD.

---

## 🛠 Pré-requisitos e Ambiente

- **Java Development Kit (JDK):** Versão 21 ou superior.
- **Servidor de Aplicação:** Red Hat JBoss Web Server 6, Tomcat 10+ ou qualquer container nativo Jakarta EE 10.
- **Maven:** Para compilação e empacotamento do projeto.

---

## ⚙️ Variáveis de Ambiente (Configuração)

A aplicação não possui *hardcodes* e foi desenhada para o princípio do 12-Factor App. Todas as configurações do container JBoss podem/devem ser injetadas por variáveis de ambiente.

### 🛡️ Configurações do Dependency-Check (Segurança & Cache)

| Variável | Obrigatória | O que faz / Impacto | Exemplo |
| :--- | :--- | :--- | :--- |
| `DPCK_DEBUG` | Opcional | Permite controlar o nível de log do JBoss e do motor do OWASP. Você pode usar os níveis padrões do Java: `trace`, `debug`, `info`, `warn` ou `error`. Para máximo detalhamento, use `debug`. Padrão: `info`. | `debug` |
| `DPCK_MAX_FILE_MB` | Opcional | Tamanho máximo em MB permitido para o upload do arquivo `.jar` ou `.war`. O teto absoluto do container é 2 GB. Padrão: `500`. | `1024` |
| `DPCK_DATA_DIR` | Recomendada | Define a pasta onde o BD H2 (gigantesco) de vulnerabilidades será guardado. **Aponte para um volume persistente**, senão o sistema baixará tudo do zero ao reiniciar. | `/var/lib/dpck-data` |
| `DPCK_THREAD_POOL_SIZE` | Opcional | Quantos scans podem rodar em paralelo. Padrão `2`. Aumentar acelera a fila, mas consome mais CPU/memória e gera concorrência no H2. | `4` |
| `DPCK_QUEUE_CAPACITY` | Opcional | Tamanho máximo da fila de scans pendentes antes de retornar 503. Padrão `10`. | `20` |
| `DPCK_UPDATE_INTERVAL_HOURS` | Opcional | Intervalo (em horas) entre atualizações automáticas da base NVD. Padrão `4`. | `6` |
| `DPCK_SCAN_TTL_MINUTES` | Opcional | TTL (minutos) para scans `COMPLETED`/`ERROR`/`CANCELLED` antes de serem removidos da memória. Padrão `120`. | `240` |
| `DPCK_SCAN_STUCK_MINUTES` | Opcional | TTL (minutos) para scans que aparentam estar travados em `RUNNING`/`QUEUED`. Padrão `240`. | `480` |
| `NVD_API_KEY` | Recomendada | Chave da API oficial do NVD. Fundamental em produção para evitar bloqueios de IP (Rate Limit) do governo americano e acelerar muito a atualização das bases. | `sua-chave-aqui-123` |
| `OSS_INDEX_USER` | Opcional | E-mail da conta do Sonatype OSS Index (caso queira varrer bancos externos além do NVD). | `seguranca@empresa.com` |
| `OSS_INDEX_PASS` | Opcional | Senha da conta do Sonatype OSS Index. | `SenhaForte` |

### 🌐 Rede Corporativa e Proxy

Se o servidor ficar isolado sem internet direta, o motor do Dependency-Check precisará saber por onde sair para baixar as atualizações do NVD.

| Variável | Obrigatória | O que faz / Impacto | Exemplo |
| :--- | :--- | :--- | :--- |
| `HTTP_PROXY_SERVER` | Opcional | O DNS ou IP do proxy. | `proxy.intranet.local` |
| `HTTP_PROXY_PORT` | Opcional | Porta do proxy. | `3128` |

---

## 📦 Como Compilar e Fazer Deploy

1. Abra o terminal no diretório do projeto e realize o empacotamento com o Maven:
   ```bash
   mvn clean package
   ```
2. Ao finalizar, o artefato estará em `target/ROOT.war`. O nome `ROOT` garante que a aplicação funcionará no "context root" (`/`) em vez de um sub-caminho.
3. **Deploy no JBoss Web Server (Tomcat):** Copie o arquivo `ROOT.war` para o diretório `webapps` do seu container.
4. Inicie o Tomcat passando as variáveis de ambiente necessárias, por exemplo:
   ```bash
   export DPCK_DATA_DIR=/var/lib/dependency-check-data
   export NVD_API_KEY=00000000-0000-0000-0000-000000000000
   export DPCK_THREAD_POOL_SIZE=2

   /opt/jboss-ews/bin/catalina.sh run
   ```

### Metadados do build (versão, git commit)

O `MANIFEST.MF` do WAR final inclui automaticamente `Implementation-Version`,
`Build-Time`, `Git-Commit`, `Git-Branch`, etc., via `git-commit-id-maven-plugin`.

- **Build local (`mvn package`)** ou **OpenShift S2I**: o plugin lê do `.git` do
  checkout. Ambos os fluxos funcionam sem configuração extra.
- **Binary build** (`oc start-build --from-dir`, sem `.git`): os campos `Git-*`
  ficam vazios — o build não falha. Implementation-Version e Build-Time
  continuam preenchidos.

Em runtime, consulte `GET /api/version` ou veja o campo `version` em
`/api/health`. Ao subir, a aplicação loga uma linha como:

```
[INFO] Build deployado: 1.0-SNAPSHOT @a1b2c3d (built 2026-05-23T15:30:42Z)
```

### Auto-escaneamento (self-scan)

A própria aplicação pode ser escaneada em busca de CVEs durante o build:

```bash
mvn verify -Pself-scan
```

Saída em `target/dependency-check-report.html` (e formatos JSON/XML).

**Implementação:** o profile invoca a classe `br.com.security.tools.SelfScan` via `exec-maven-plugin`. Essa classe usa a biblioteca `dependency-check-core` que **já está declarada com range aberto `[10.0.0,)`** — ou seja, o self-scan **sempre roda na versão mais recente da engine disponível no Maven Central**, sem precisar pinar o plugin `dependency-check-maven` (que Maven 3.9+ exige versão fixa).

Para fazer o build falhar quando qualquer CVE for encontrada:

```bash
mvn verify -Pself-scan -Dselfscan.failOnAnyCve=true
```

Por padrão o build não falha — o objetivo é gerar o relatório para inspeção. Se quiser thresholding por CVSS (ex.: falhar só se CVSS ≥ 9), edite `SelfScan.java` para somar pontuação.

---

## 🌐 Endpoints

| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `POST` | `/api/scan` | Recebe multipart com `file` (`.jar`/`.war`). Retorna `{"scanId": "..."}`. |
| `GET` | `/api/status?id=<uuid>` | Status atual do scan (`QUEUED`, `RUNNING`, `COMPLETED`, `ERROR`, `CANCELLED`). |
| `POST` | `/api/cancel?id=<uuid>` | Cancela o scan (mesmo se já em andamento). |
| `GET` | `/api/report?id=<uuid>` | Baixa o relatório HTML (force `attachment`, anti-XSS). **Política no-re-download estrita:** o relatório é apagado do servidor após o download (sucesso ou falha de stream). `HEAD` não consome. |
| `GET` | `/api/health[?strict=true]` | Saúde da aplicação. Com `strict=true` retorna 503 quando degradado. Inclui `version` (resumo do build). |
| `GET` | `/api/metrics` | Contadores: uploads, scans, NVD, heap. |
| `GET` | `/api/version` | Metadados do build lidos do `MANIFEST.MF` (versão, commit, branch, build time). |

---

## 🏗️ Arquitetura Interna do Sistema

- **`br.com.security.AppContextListener`**: `@WebListener` que gerencia o ciclo de vida da aplicação. Cria o pool de threads compartilhado para scans, inicia o `ScanManager` e o `DatabaseUpdater`, e faz *shutdown* ordenado com `awaitTermination`.
- **`br.com.security.UploadServlet`** (Servlet 6.0): Recebe o arquivo em Multipart, valida (tamanho, extensão, magic bytes ZIP), responde imediatamente com `scanId` e enfileira a tarefa no pool gerenciado pelo `AppContextListener`.
- **`br.com.security.DependencyCheckRunner`**: Encapsula e configura o motor embarcado `Engine`. Possui *progress smoother* que avança o progresso entre os *checkpoints* do motor para feedback visual contínuo.
- **`br.com.security.DatabaseUpdater`**: Bootstrap inicial assíncrono + agendamento periódico (`DPCK_UPDATE_INTERVAL_HOURS`). Usa `ReentrantReadWriteLock` para coordenar com scans em andamento.
- **`br.com.security.ScanManager`**: Registro central dos scans em memória (TTL configurável, *cleaner* periódico, suporte a cancelamento).
- **`br.com.security.StatusServlet`/`ReportServlet`/`CancelServlet`/`HealthServlet`/`MetricsServlet`**: Endpoints REST com validação UUID, respostas JSON padronizadas (Jackson) e cabeçalhos `no-store`/`nosniff`.
- **`br.com.security.SecurityHeadersFilter`** (`@WebFilter("/*")`): Aplica CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy a todas as respostas.
- **`br.com.security.LogUtils`**: Fachada para SLF4J — alinha logs da aplicação com o motor do dependency-check em um único formato configurado por `DPCK_DEBUG`.
- **`br.com.security.Metrics`**: Contadores `AtomicLong` expostos via `/api/metrics`.

Feito para alta performance e estabilidade!
