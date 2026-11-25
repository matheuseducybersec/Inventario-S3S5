"""
Três testes com pytest, um para cada parte central do trabalho.

    1. Requisito 4 — o risco calculado pela API bate com a conta feita à mão.
    2. Requisito 4 — o modelo detecta quando I - A não é invertível.
    3. Requisitos 1 e 2 — os objetos vão para o JSON como array e voltam
       como objetos da subclasse certa (herança + polimorfismo).

Rodar:            pytest -v
Gerar relatório:  pytest -v --html=relatorios/relatorio_testes.html --self-contained-html
"""

import json

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app import api
from app.demo import carregar_demo
from app.inventario import Inventario
from app.modelos import AplicacaoWeb, BancoDeDados, Notebook
from app.risco import ModeloRisco, SistemaNaoInvertivel


# ---------------------------------------------------------------------
# Fixtures: cada teste recebe uma pasta temporária, sem tocar nos dados reais
# ---------------------------------------------------------------------
@pytest.fixture
def pasta_demo(tmp_path):
    """Pasta com o cenário de 3 equipamentos resolvido à mão no README."""
    carregar_demo(tmp_path)
    return tmp_path


@pytest.fixture
def cliente(pasta_demo, monkeypatch):
    """Cliente HTTP da API apontando para a pasta temporária."""
    monkeypatch.setattr(api, "PASTA_DADOS", str(pasta_demo))
    return TestClient(api.app)


# ---------------------------------------------------------------------
# Teste 1 — API: risco próprio e efetivo iguais ao cálculo à mão
# ---------------------------------------------------------------------
def test_api_risco_bate_com_calculo_a_mao(cliente):
    """b = F·M·v = (16.8, 6, 4) e x = (I - A)^-1 b = (22, 10.4, 6.2)."""
    resposta = cliente.get("/risco")
    assert resposta.status_code == 200

    dados = resposta.json()
    assert dados["diagnostico"]["invertivel"] is True
    assert dados["diagnostico"]["determinante"] == pytest.approx(0.9)

    proprio = [e["risco_proprio"] for e in dados["equipamentos"]]
    efetivo = [e["risco_efetivo"] for e in dados["equipamentos"]]
    assert proprio == pytest.approx([16.8, 6.0, 4.0])
    assert efetivo == pytest.approx([22.0, 10.4, 6.2])

    # A regra da soma das linhas < 1 também é aplicada pela API (HTTP 422)
    recusada = cliente.put("/dependencias", json={"dependente": 1, "origem": 3, "fracao": 0.6})
    assert recusada.status_code == 422


# ---------------------------------------------------------------------
# Teste 2 — invertibilidade: singular é recusada, quase singular gera aviso
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "A, invertivel, trecho_mensagem",
    [
        ([[0, 0.5], [0.2, 0]], True, "bem condicionada"),                       # caso normal
        ([[0, 1 - 1e-12], [1 - 1e-12, 0]], True, "MAL CONDICIONADA"),            # det ≈ 2e-12
        ([[0, 1], [1, 0]], False, "singular"),                                  # det = 0
    ],
    ids=["bem_condicionada", "quase_singular", "singular"],
)
def test_verificacao_de_invertibilidade(A, invertivel, trecho_mensagem):
    modelo = ModeloRisco(M=[[1], [1]], v=[5.0], A=A)
    diagnostico = modelo.diagnosticar()

    assert diagnostico.invertivel is invertivel
    assert trecho_mensagem in diagnostico.mensagem
    if invertivel:
        x = modelo.resolver().matrizes["x"]
        # confere a própria equação: (I - A) x = b
        assert np.allclose((np.eye(2) - np.array(A)) @ x, modelo.risco_proprio())
    else:
        with pytest.raises(SistemaNaoInvertivel):
            modelo.resolver()


# ---------------------------------------------------------------------
# Teste 3 — persistência JSON + herança/polimorfismo
# ---------------------------------------------------------------------
def test_json_array_e_objetos_das_subclasses(pasta_demo):
    arquivo = pasta_demo / "equipamentos.json"
    conteudo = json.loads(arquivo.read_text(encoding="utf-8"))

    # Requisito 2: o arquivo é um ARRAY de objetos JSON
    assert isinstance(conteudo, list)
    assert all(isinstance(item, dict) for item in conteudo)
    assert [item["tipo"] for item in conteudo] == ["aplicacao_web", "banco_de_dados", "notebook"]

    # Requisito 1: ao recarregar, cada item volta como objeto da sua subclasse
    inventario = Inventario(pasta_demo)
    objetos = inventario.listar_equipamentos()
    assert [type(o) for o in objetos] == [AplicacaoWeb, BancoDeDados, Notebook]

    # Polimorfismo: mesma chamada, valor diferente por classe
    assert [o.fator_exposicao for o in objetos] == [1.2, 1.0, 0.8]
