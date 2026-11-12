# Inventário de Ativos de TI e Análise de Risco

2ª Atividade Avaliativa (Sprints 3, 4 e 5) — Bacharelado em Cibersegurança, UFU, 2026/2
Continuação do [Trabalho 1](https://github.com/matheuseducybersec/Inventario-S1S2), agora:

1. reescrito em **orientação a objetos** (herança, classe abstrata, polimorfismo, encapsulamento);
2. executado em um **container Docker** (API HTTP que fica no ar continuamente);
3. com um **modelo de risco por álgebra linear**: `(I − A)·x = b`.

---

## Estrutura

```
app/
├── modelos.py      Equipamento (abstrata) + 6 subclasses, Vulnerabilidade, Dependencia
├── repositorio.py  RepositorioJSON: lê/grava listas de objetos em arquivos JSON
├── inventario.py   Inventario: regras de negócio (CRUD, integridade, regra das dependências)
├── risco.py        ModeloRisco: monta M, v, A; verifica invertibilidade; resolve o sistema
├── api.py          API HTTP (FastAPI) — processo principal do container
├── cli.py          Menu textual (mesma lógica do Trabalho 1)
└── demo.py         Carrega o cenário de validação resolvido à mão
tests/test_risco.py Testes automáticos (unittest)
Dockerfile, docker-compose.yml, requirements.txt
```

Arquitetura em camadas — as interfaces (API e CLI) só conversam com `Inventario`;
só o `RepositorioJSON` toca nos arquivos:

```
  API (api.py) ─┐
                ├─► Inventario ─► RepositorioJSON ─► data/*.json
  CLI (cli.py) ─┘        │
                         └─► ModeloRisco (numpy)
```

---

## Requisitos da Tabela 1

| Nº | Requisito | Onde está |
|----|-----------|-----------|
| 1 | Classe de equipamentos e objetos derivados | `app/modelos.py`: `Equipamento` (abstrata) → `Notebook`, `Servidor`, `Roteador`, `AplicacaoWeb`, `BancoDeDados`, `ImpressoraRede` |
| 2 | Armazenamento em JSON, array de objetos | `app/repositorio.py`; arquivos `data/equipamentos.json`, `vulnerabilidades.json`, `dependencias.json` |
| 3 | Execução em container por 24 h | `Dockerfile` + `docker-compose.yml` (`restart: unless-stopped`, `HEALTHCHECK`, rota `/health` com `uptime_horas`) |
| 4 | Risco efetivo via modelo linear, com verificação de invertibilidade | `app/risco.py`; rotas `GET /risco` e `GET /risco/{id}`; opções 12 e 13 da CLI |

---

## Como executar

### Com Docker (forma oficial)

```bash
docker compose up -d --build                       # constrói e sobe em segundo plano
docker exec inventario python -m app.demo          # (opcional) carrega o cenário de exemplo
docker ps                                          # STATUS deve mostrar "(healthy)"
```

- API e documentação interativa: <http://localhost:8000/docs>
- Menu textual dentro do container: `docker exec -it inventario python -m app.cli`
- Testes dentro do container: `docker exec inventario python -m unittest -v`
- Logs: `docker logs -f inventario` — Parar: `docker compose down`

Sem o `docker compose`:

```bash
docker build -t inventario-risco:2.0 .
docker run -d --name inventario --restart unless-stopped -p 8000:8000 -v inventario_dados:/app/data inventario-risco:2.0
```

### Sem Docker (desenvolvimento)

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (Linux: source .venv/bin/activate)
pip install -r requirements.txt
python -m unittest -v             # testes
python -m app.demo                # cenário de exemplo
python -m app.cli                 # menu
uvicorn app.api:app --reload      # API em http://127.0.0.1:8000/docs
```

### No servidor da disciplina (10.0.99.150)

```bash
ssh <matricula>@10.0.99.150
git clone https://github.com/matheuseducybersec/Inventario-S3S5.git
cd Inventario-S3S5
docker compose up -d --build
docker exec inventario python -m app.demo
curl http://localhost:8000/health        # repetir após 24 h: uptime_horas >= 24
```

---

## Rotas da API

| Método | Rota | Função |
|--------|------|--------|
| GET | `/health` | Estado e tempo no ar |
| GET | `/tipos` | Tipos de equipamento |
| GET/POST | `/equipamentos` | Listar (filtro `?hostname=`) / cadastrar |
| GET/PUT/DELETE | `/equipamentos/{id}` | Consultar (com vulnerabilidades) / atualizar / remover |
| GET/POST | `/vulnerabilidades` | Listar / cadastrar |
| POST/DELETE | `/vulnerabilidades/{id}/equipamentos/{eq}` | Associar / desassociar |
| PATCH | `/vulnerabilidades/{id}/status` | Mudar status |
| DELETE | `/vulnerabilidades/{id}` | Remover |
| GET/PUT | `/dependencias` | Listar / criar ou alterar |
| DELETE | `/dependencias/{dependente}/{origem}` | Remover |
| GET | `/risco` (`?matrizes=true`) | Risco próprio e efetivo de todos |
| GET | `/risco/{id}` | Risco de um equipamento |

Erros: `404` (não encontrado), `422` (dado inválido), `409` (I − A não invertível).

---

## Modelo de risco

| Símbolo | Significado | Origem |
|---|---|---|
| `M` (n×m) | `M[i][j] = 1` se o equipamento *i* tem a vulnerabilidade *j* | lista `equipamentos` de cada vulnerabilidade |
| `v` (m) | severidade (CVSS 0–10) | campo `cvss` |
| `f` (n) | fator de exposição do tipo de equipamento | **polimorfismo**: `equipamento.fator_exposicao` |
| `b = F·M·v` | risco próprio (`F = diag(f)`) | |
| `A` (n×n) | `A[i][j]` = fração do risco de *j* que passa para *i* | `dependencias.json` |
| `x` | risco efetivo: `x = b + A·x  ⇔  (I − A)·x = b` | `numpy.linalg.solve` |

Fatores de exposição: Aplicação Web 1.2 · Roteador 1.1 · Servidor 1.0 · Banco de Dados 1.0 · Notebook 0.8 · Impressora 0.5.

**Invertibilidade.**
- No cadastro, a soma de cada linha de `A` é obrigatoriamente `< 1`. Com `A_ii = 0`, isso torna `I − A`
  *estritamente diagonal dominante* e, pelo teorema de Lévy–Desplanques, invertível.
- Antes de resolver, o programa calcula `det(I − A)` e o **número de condição** `cond(I − A)`.
  Não se compara o determinante com zero: em ponto flutuante ele quase nunca dá zero exato, e o
  valor depende da escala da matriz. O número de condição diz quantos dígitos se perdem
  (≈ `log10(cond)`): acima de `1/ε ≈ 4,5·10¹⁵` o sistema é tratado como singular (o usuário é avisado,
  HTTP 409); acima de `10⁸` o resultado sai com aviso de matriz mal condicionada.
- O sistema é resolvido com `solve` (fatoração LU), mais preciso e barato que `inv(I − A) @ b`.

### Validação à mão (cenário de `python -m app.demo`)

| ID | Equipamento | Tipo (fator) | Vulnerabilidades (CVSS) |
|---|---|---|---|
| 1 | APP-PORTAL | Aplicação Web (1.2) | V1 (8.0), V2 (6.0) |
| 2 | DB-ACADEMICO | Banco de Dados (1.0) | V2 (6.0) |
| 3 | NB-SECRETARIA | Notebook (0.8) | V3 (5.0) |

Dependências: 1 herda 0.5 de 2 · 2 herda 0.2 de 1 · 3 herda 0.1 de 1 (há um ciclo 1 ↔ 2).

```
M = | 1 1 0 |   v = | 8 |   M·v = | 14 |   b = F·M·v = | 1.2·14 | = | 16.8 |
    | 0 1 0 |       | 6 |         |  6 |               | 1.0·6  |   |  6.0 |
    | 0 0 1 |       | 5 |         |  5 |               | 0.8·5  |   |  4.0 |

A = | 0   0.5 0 |      I − A = |  1   −0.5  0 |   det(I − A) = 1 − 0.5·0.2 = 0.9 ≠ 0
    | 0.2 0   0 |              | −0.2  1    0 |
    | 0.1 0   0 |              | −0.1  0    1 |

x1 = 16.8 + 0.5·x2
x2 =  6.0 + 0.2·x1      →  x1 = 16.8 + 0.5·(6 + 0.2·x1) = 19.8 + 0.1·x1  →  x1 = 22
x3 =  4.0 + 0.1·x1      →  x2 = 6 + 4.4 = 10.4      x3 = 4 + 2.2 = 6.2
```

Resultado: **x = (22; 10,4; 6,2)**, idêntico ao calculado pelo programa (`tests/test_risco.py`).

---

Autor: Matheus Eduardo — github.com/matheuseducybersec
