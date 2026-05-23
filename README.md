# SecCheck - Scanner de Vulnerabilidades NVD/OSS (OWASP Dependency-Check)

O **SecCheck** é uma aplicação corporativa robusta construída para auxiliar equipes de Segurança da Informação. A aplicação permite que usuários façam o upload de arquivos `.jar` ou `.war` via interface web e automaticamente roda o motor do **OWASP Dependency-Check Core** de forma embarcada e concorrente, exibindo o status de progresso ao vivo na tela e disponibilizando o relatório final (HTML) para download.

---

## 🚀 Principais Funcionalidades

- **100% Self-Contained:** O motor do OWASP Dependency-Check (`dependency-check-core`) está embutido no projeto. Não é necessário instalar nenhuma ferramenta de linha de comando no servidor JBoss/Tomcat.
- **Interface Web "Glassmorphism":** Design moderno com modo escuro, animações suaves e arrastar/soltar (Drag-and-Drop).
- **Alta Concorrência e Proteção de Memória:** Como a análise gasta muita memória e CPU, a aplicação utiliza um Pool de Threads de tamanho fixo para processar a fila de arquivos, evitando o *Crash* (OutOfMemory) do servidor.
- **Atualização Inteligente do NVD:** O banco de dados do NVD é mantido localmente. Através de um Agendador em Segundo Plano, o Tomcat atualiza silenciosamente os novos CVEs a cada **4 horas**.
- **Acompanhamento em Tempo Real:** O Front-End da aplicação efetua Polling para a API demonstrando exatamente a situação ("Fila", "Analisando dependências...", "Concluído") e servindo o download do arquivo.
- **Segurança de Thread (Locks):** Utilização de `ReentrantReadWriteLock`. Inúmeras análises podem ser feitas paralelamente (Read Lock). A fila só pausa por alguns segundos durante as janelas de 4h em que ocorre a escrita (Write Lock) para atualizar as bases do NVD.

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

1. Abra o terminal no diretório do projeto:
   ```bash
   cd /home/antigerme/Documentos/dpck
   ```
2. Realize o empacotamento com o Maven:
   ```bash
   mvn clean package
   ```
3. Ao finalizar, o artefato estará em `target/ROOT.war`. O nome `ROOT` garante que a aplicação funcionará no "context root" (`/`) em vez de um sub-caminho.
4. **Deploy no JBoss Web Server (Tomcat):** Copie o arquivo `ROOT.war` para o diretório `webapps` do seu container.
5. Inicie o Tomcat passando as variáveis de ambiente necessárias, por exemplo:
   ```bash
   export DPCK_DATA_DIR=/var/lib/dependency-check-data
   export NVD_API_KEY=00000000-0000-0000-0000-000000000000
   export SMTP_HOST=smtp.intranet.empresa
   export SMTP_PORT=25
   export SMTP_FROM=seccheck@intranet.empresa
   
   /opt/jboss-ews/bin/catalina.sh run
   ```

---

## 🏗️ Arquitetura Interna do Sistema

- **`br.com.security.UploadServlet`**: (Servlet 6.0) Recebe o arquivo em Multipart, responde o usuário imediatamente com o status (UI Async) e envia o pacote de bytes pra fila interna gerenciada por um Pool Fixo (`FixedThreadPool(4)`).
- **`br.com.security.DependencyCheckRunner`**: Encapsula e configura o motor embarcado `Engine`.
- **`br.com.security.DatabaseUpdater`**: `@WebListener` que executa a cada 4 horas. Invoca o `Engine.doUpdates()` garantindo sincronismo.
- **`br.com.security.EmailService`**: Prepara a mensagem via Jakarta Mail API, enviando o `dependency-check-report.html` como anexo (MIME type attachments).

Feito para alta performance e estabilidade!
