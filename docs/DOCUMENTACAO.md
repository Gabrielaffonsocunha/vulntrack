# Documentação — VulnTrack

## 1. Visão geral

O VulnTrack é um projeto demonstrativo para registrar vulnerabilidades de ativos fictícios e acompanhar prioridade, prazo, responsável e plano de tratamento. Ele foi criado para estudo e portfólio; não substitui uma plataforma de gestão de vulnerabilidades pronta para produção.

O projeto reúne uma API REST, um painel web responsivo, persistência SQLite e execução local opcional em Docker. Os registros iniciais e os nomes dos ativos são dados de demonstração.

## 2. Funcionalidades

- Painel com total de registros, itens em aberto, críticas em aberto e prazos vencidos.
- Busca por título, CVE, ativo ou responsável.
- Filtros por status e criticidade.
- Cadastro, mudança de status e exclusão de registros demonstrativos.
- Exportação do inventário para CSV.
- Persistência local em SQLite.
- Documentação interativa da API pelo Swagger em `/docs`.

## 3. Tecnologias e estrutura

- Python 3.12, FastAPI, Pydantic e SQLite.
- HTML, CSS e JavaScript sem framework.
- Docker Compose e GitHub Actions.
- Testes automatizados com `unittest` e `fastapi.testclient`.

```text
app.py                         API, validação, regras e acesso ao SQLite
static/index.html              Estrutura do painel e formulário
static/styles.css              Layout responsivo e identidade visual
static/app.js                  Chamadas da API, filtros e exportação CSV
tests/test_app.py              Testes de API e regras de status
Dockerfile                     Imagem da aplicação
docker-compose.yml             Inicialização local isolada
.github/workflows/validate.yml Testes automáticos em pushes e pull requests
```

O painel não carrega bibliotecas, fontes nem imagens de terceiros. Isso evita chamadas externas do navegador ao abrir a interface.

## 4. Instalação e execução

### Opção A — Docker Compose

Requisitos: Docker Engine e Docker Compose v2.

```bash
docker compose up --build
```

Abra `http://localhost:8000`. A documentação da API fica em `http://localhost:8000/docs`, e o health check fica em `http://localhost:8000/health`.

O Compose publica a porta em `127.0.0.1` e persiste o banco no volume `vulntrack-data`. Para encerrar a aplicação sem apagar dados:

```bash
docker compose down
```

Para apagar também o volume local:

```bash
docker compose down -v
```

O container roda como usuário sem privilégios, com filesystem somente leitura e sem capabilities adicionais. O volume de dados e o diretório temporário são graváveis conforme necessário.

### Opção B — execução direta com Python

```bash
python -m venv .venv
```

Ative o ambiente virtual:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Instale dependências e inicie a API:

```bash
pip install -r requirements.txt
uvicorn app:app --reload
```

Por padrão, a aplicação cria `data/vulntrack.db`. Para usar outro caminho, defina `VULNTRACK_DB` antes de iniciar o servidor.

## 5. Modelo de dados

Cada registro contém:

| Campo | Descrição |
| --- | --- |
| `id` | Identificador numérico do registro |
| `title` | Resumo da vulnerabilidade, obrigatório |
| `cve` | Identificador CVE opcional; precisa seguir o formato `CVE-AAAA-NNNN` |
| `asset` | Nome fictício do ativo afetado, obrigatório |
| `severity` | Criticidade: Crítica, Alta, Média ou Baixa |
| `cvss` | Pontuação opcional entre 0 e 10 |
| `status` | Etapa atual do tratamento |
| `due_date` | Data de acompanhamento opcional, no formato ISO `AAAA-MM-DD` |
| `owner` | Responsável ou equipe, opcional |
| `mitigation` | Plano de tratamento, até 1.500 caracteres |
| `created_at`, `updated_at` | Marcas de tempo em UTC |

Os marcadores `CVE-2099-*` apresentados inicialmente são fictícios e não apontam para vulnerabilidades reais.

## 6. Regras de negócio

Status disponíveis:

- `Aberta`
- `Em análise`
- `Em correção`
- `Validada`
- `Aceita`

Transições permitidas:

| Status atual | Próximas etapas |
| --- | --- |
| Aberta | Em análise, Aceita |
| Em análise | Em correção, Aceita, Aberta |
| Em correção | Validada, Em análise, Aceita |
| Validada | Aberta |
| Aceita | Aberta, Em análise |

Transição não permitida retorna `409 Conflict`. Os indicadores consideram como abertos os registros que não estão em `Validada` ou `Aceita`. Um prazo vencido é calculado pela data local do servidor que executa a API.

## 7. Endpoints

| Método | Rota | Uso |
| --- | --- | --- |
| `GET` | `/health` | Confirma que a API responde |
| `GET` | `/api/summary` | Retorna os quatro indicadores do painel |
| `GET` | `/api/vulnerabilities` | Lista os registros |
| `POST` | `/api/vulnerabilities` | Cria um registro |
| `PATCH` | `/api/vulnerabilities/{id}/status` | Atualiza o status dentro do fluxo permitido |
| `DELETE` | `/api/vulnerabilities/{id}` | Exclui um registro local |

### Filtros da listagem

`GET /api/vulnerabilities` aceita `status`, `severity` e `search`.

```text
/api/vulnerabilities?status=Aberta&severity=Crítica&search=app-demo
```

### Exemplo de cadastro

```json
{
  "title": "Pacote de demonstração desatualizado",
  "cve": "CVE-2099-99999",
  "asset": "app-demo-05",
  "severity": "Alta",
  "cvss": 7.5,
  "due_date": "2026-12-10",
  "owner": "Equipe de aplicação",
  "mitigation": "Avaliar atualização em ambiente de teste e registrar a validação."
}
```

O registro começa com status `Aberta`. Os dados de exemplo acima não descrevem um sistema real.

## 8. Testes e validação

Execute os testes com:

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Os testes cobrem a carga inicial, indicadores, criação e busca, validação do identificador CVE, transições permitidas e bloqueadas, e exclusão.

O workflow `Validate VulnTrack` repete os testes em cada push e pull request. O pipeline valida a API e as regras testadas; não substitui teste de carga, teste de segurança ou execução do container em uma infraestrutura real.

## 9. Segurança, privacidade e limites

- Use somente dados fictícios na demonstração pública.
- A aplicação não tem autenticação, perfis, trilha de auditoria ou proteção para múltiplos usuários.
- Não inclua hosts, IPs, evidências, nomes de pessoas ou informações internas da empresa.
- A aplicação não faz upload de arquivos e não consulta serviços externos.
- O SQLite é adequado ao laboratório local de instância única, não a acesso concorrente de vários usuários.
- O binding do Compose em `127.0.0.1` limita a interface ao host local. Não exponha a API diretamente à internet.
- Antes de qualquer uso compartilhado, seria necessário projetar autenticação, autorização, auditoria, backup, gestão de segredos, banco multiusuário e revisão de segurança.

## 10. Solução de problemas

**A página abre, mas não carrega registros:** confira se a API iniciou e teste `http://localhost:8000/health`.

**A porta 8000 já está em uso:** encerre o outro serviço ou altere a porta publicada no `docker-compose.yml` e acesse a nova porta.

**O banco precisa ser reiniciado com os dados de exemplo:** pare a stack, remova o volume com `docker compose down -v` e inicie novamente. Isso apaga os registros locais.

**Um status não pode ser alterado:** consulte a tabela de transições. A API retorna HTTP `409` para mudanças fora do fluxo.

## 11. Próximas evoluções

1. Histórico de alterações por registro.
2. Edição dos demais campos depois do cadastro.
3. Paginação e busca combinada por campos.
4. Autenticação e perfis em um ambiente de demonstração multiusuário.
5. Migração para PostgreSQL e migrações de esquema se houver necessidade real.
6. Integração opcional com fontes CVE públicas, com validação, cache e indicação clara da fonte.
