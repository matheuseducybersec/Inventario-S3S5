# Relatório de Testes

**Projeto:** Inventário de Ativos e Análise de Risco (Trabalho 2, Cibersegurança/UFU)
**Autor:** Matheus Eduardo
**Data da execução:** 25/11/2026
**Ferramenta:** pytest 8.4.2 + pytest-html 4.1.1

| Resultado | Valor |
|---|---|
| Testes executados | **17** |
| Aprovados | **17** |
| Falhas | 0 |
| Erros | 0 |
| Tempo total | ≈ 2 s |

Arquivos gerados nesta pasta:

- [`relatorio_testes.html`](relatorio_testes.html): relatório completo do pytest-html (abrir no navegador)
- [`relatorio_testes.xml`](relatorio_testes.xml): mesmo resultado no formato JUnit XML

---

## 1. Os três testes com pytest (`tests/test_pytest.py`)

| # | Teste | Requisito | O que verifica |
|---|---|---|---|
| 1 | `test_api_risco_bate_com_calculo_a_mao` | 4 | Pela **API** (`GET /risco`), o risco próprio é **b = (16,8; 6,0; 4,0)**, o efetivo é **x = (22,0; 10,4; 6,2)** e **det(I − A) = 0,9**, iguais ao cálculo feito à mão no README. Também confirma que a API recusa (HTTP 422) uma dependência que faria a soma da linha de A passar de 1. |
| 2 | `test_verificacao_de_invertibilidade` (3 casos) | 4 | Matriz **bem condicionada**: resolve e confere (I − A)x = b. Matriz **quase singular** (det ≈ 2·10⁻¹²): resolve, mas avisa que está **mal condicionada**. Matriz **singular** (det = 0): o sistema **não** é resolvido e o programa lança `SistemaNaoInvertivel`. |
| 3 | `test_json_array_e_objetos_das_subclasses` | 1 e 2 | O arquivo `equipamentos.json` é um **array de objetos JSON**. Ao recarregar, cada item volta como objeto da **subclasse correta** (`AplicacaoWeb`, `BancoDeDados`, `Notebook`), e cada um responde o seu `fator_exposicao` (1,2 / 1,0 / 0,8), ou seja, o **polimorfismo** funciona. |

Recursos do pytest usados:

- **fixtures** (`pasta_demo`, `cliente`): preparam o cenário em uma pasta temporária (`tmp_path`), sem tocar nos dados reais;
- **monkeypatch**: aponta a API para essa pasta temporária;
- **parametrize**: roda o teste 2 com três matrizes diferentes;
- **pytest.approx** e **pytest.raises**: comparam números de ponto flutuante e verificam exceções.

## 2. Testes anteriores (`tests/test_risco.py`, unittest)

O pytest também executa os 12 testes escritos com `unittest`:

| Grupo | Testes | O que verificam |
|---|---|---|
| Cenário manual | 6 | Risco próprio e efetivo, determinante e número de condição, JSON como array, regra da soma das linhas < 1, integridade ao remover equipamento |
| Invertibilidade | 3 | Matriz singular, quase singular e inventário vazio |
| Orientação a objetos | 3 | Classe abstrata, polimorfismo dos 6 tipos, validações |

## 3. Ambiente

| Item | Versão |
|---|---|
| Sistema | Windows 11 |
| Python | 3.14 |
| numpy | 2.3.4 |
| fastapi | 0.115.12 |
| uvicorn | 0.34.3 |
| pytest / pytest-html / httpx | 8.4.2 / 4.1.1 / 0.28.1 |

## 4. Situação no servidor (requisito 3)

Na data deste relatório, o container `inventario-12621cbs203` estava no ar no servidor
`10.0.99.150` (porta 8203) **sem interrupção desde 17/11/2026 às 20:12**, com
**`uptime_horas` = 191**. O requisito de 24 horas está cumprido com folga.

## 5. Como reproduzir

```bash
pip install -r requirements-dev.txt
pytest -v --html=relatorios/relatorio_testes.html --self-contained-html --junitxml=relatorios/relatorio_testes.xml
```
