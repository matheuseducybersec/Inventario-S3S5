"""
Validação do modelo de risco com o cenário pequeno resolvido À MÃO (ver README).

Rodar:  python -m unittest -v
"""

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from app.demo import carregar_demo
from app.inventario import Inventario
from app.modelos import AplicacaoWeb, Equipamento, ErroValidacao, Notebook
from app.risco import ModeloRisco, SistemaNaoInvertivel


class TestCenarioManual(unittest.TestCase):
    """3 equipamentos, 3 vulnerabilidades, 3 dependências (com ciclo 1<->2)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.inv = carregar_demo(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_risco_proprio(self):
        # M·v = [8+6, 6, 5] = [14, 6, 5];  fatores = [1.2, 1.0, 0.8]
        r = self.inv.calcular_risco()
        self.assertEqual([e.risco_bruto for e in r.equipamentos], [14.0, 6.0, 5.0])
        np.testing.assert_allclose([e.risco_proprio for e in r.equipamentos], [16.8, 6.0, 4.0])

    def test_risco_efetivo(self):
        # x1 = 16.8 + 0.5 x2 ; x2 = 6 + 0.2 x1 ; x3 = 4 + 0.1 x1
        # => 0.9 x1 = 19.8 => x1 = 22 ; x2 = 10.4 ; x3 = 6.2
        r = self.inv.calcular_risco()
        np.testing.assert_allclose([e.risco_efetivo for e in r.equipamentos], [22.0, 10.4, 6.2])

    def test_determinante_e_condicao(self):
        d = self.inv.calcular_risco().diagnostico
        self.assertTrue(d.invertivel)
        self.assertTrue(d.diagonal_dominante)
        self.assertAlmostEqual(d.determinante, 0.9)   # 1 - 0.5*0.2
        self.assertLess(d.numero_condicao, 10)

    def test_persistencia_e_array_json(self):
        # REQUISITO 2: cada arquivo é um array de objetos JSON
        for nome in ("equipamentos.json", "vulnerabilidades.json", "dependencias.json"):
            dados = json.loads((Path(self.tmp.name) / nome).read_text(encoding="utf-8"))
            self.assertIsInstance(dados, list)
            self.assertTrue(all(isinstance(item, dict) for item in dados))
        # Recarregar do disco recria objetos das subclasses corretas
        novo = Inventario(self.tmp.name)
        self.assertIsInstance(novo.obter_equipamento(1), AplicacaoWeb)
        self.assertIsInstance(novo.obter_equipamento(3), Notebook)

    def test_regra_soma_linha(self):
        # Equipamento 1 já herda 0.5 do 2; mais 0.6 do 3 daria 1.1 >= 1
        with self.assertRaises(ErroValidacao):
            self.inv.definir_dependencia(dependente=1, origem=3, fracao=0.6)

    def test_remocao_mantem_integridade(self):
        self.inv.remover_equipamento(1)
        self.assertNotIn(1, self.inv.obter_vulnerabilidade(2).equipamentos)
        self.assertFalse(any(1 in k for k in self.inv.dependencias))
        r = self.inv.calcular_risco()
        np.testing.assert_allclose([e.risco_efetivo for e in r.equipamentos], [6.0, 4.0])


class TestInvertibilidade(unittest.TestCase):
    def test_matriz_singular(self):
        # A = [[0,1],[1,0]] => I - A = [[1,-1],[-1,1]], det = 0
        modelo = ModeloRisco(M=[[1], [1]], v=[5], A=[[0, 1], [1, 0]])
        with self.assertRaises(SistemaNaoInvertivel):
            modelo.resolver()

    def test_quase_singular_mal_condicionada(self):
        # Teoricamente invertível, mas det ≈ 2e-12: o número de condição denuncia
        a = 1 - 1e-12
        modelo = ModeloRisco(M=[[1], [1]], v=[5], A=[[0, a], [a, 0]])
        d = modelo.diagnosticar()
        self.assertTrue(d.invertivel)
        self.assertGreater(d.numero_condicao, 1e8)
        self.assertIn("MAL CONDICIONADA", d.mensagem)

    def test_sem_equipamentos(self):
        r = ModeloRisco(M=np.zeros((0, 0)), v=[], A=np.zeros((0, 0))).resolver()
        self.assertEqual(r.equipamentos, [])


class TestOrientacaoObjetos(unittest.TestCase):
    def test_classe_abstrata(self):
        with self.assertRaises(TypeError):
            Equipamento(1, "x", "y", "z")

    def test_polimorfismo(self):
        fatores = {t: c(1, "h", "r", "s").fator_exposicao
                   for t, c in Equipamento.tipos_disponiveis().items()}
        self.assertEqual(len(fatores), 6)
        self.assertEqual(fatores["aplicacao_web"], 1.2)

    def test_validacoes(self):
        with self.assertRaises(ErroValidacao):
            Equipamento.criar("notebook", id=1, hostname="", responsavel="r", setor="s")
        with self.assertRaises(ErroValidacao):
            Equipamento.criar("geladeira", id=1, hostname="h", responsavel="r", setor="s")


if __name__ == "__main__":
    unittest.main()
