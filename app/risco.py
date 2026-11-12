"""
REQUISITO 4 — Modelo linear de análise de risco.

    M  (n x m)  matriz de incidência: M[i][j] = 1 se o equipamento i tem a vulnerabilidade j
    v  (m)      vetor de severidade (nota CVSS de cada vulnerabilidade)
    f  (n)      fator de exposição de cada equipamento (vem do POLIMORFISMO)
    b  (n)      risco próprio:  b = F · M · v,  com F = diag(f)
    A  (n x n)  dependências:  A[i][j] = fração do risco de j transmitida a i
    x  (n)      risco efetivo:  x = b + A·x   <=>   (I - A)·x = b

Passos (enunciado):
  a) montar M, v e A a partir dos dados persistidos   -> a_partir_do_inventario()
  b) verificar se I - A é invertível                 -> diagnosticar()
  c) resolver o sistema e mostrar b e x               -> resolver()
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

# Se cond(I - A) passar disso, o sistema é tratado como NUMERICAMENTE singular:
# 1/eps ≈ 4.5e15 significa que todos os ~16 dígitos do float64 podem estar errados.
LIMITE_SINGULAR = 1.0 / np.finfo(float).eps
# Acima disso, avisamos que a solução perde precisão (≈ log10(cond) dígitos).
LIMITE_MAL_CONDICIONADO = 1e8


class SistemaNaoInvertivel(ArithmeticError):
    """I - A é singular (ou numericamente singular): o sistema não tem solução única."""

    def __init__(self, diagnostico: "Diagnostico"):
        super().__init__(diagnostico.mensagem)
        self.diagnostico = diagnostico


@dataclass
class Diagnostico:
    invertivel: bool
    determinante: float
    numero_condicao: float
    diagonal_dominante: bool
    mensagem: str

    def to_dict(self) -> dict:
        cond = self.numero_condicao
        return {
            "invertivel": self.invertivel,
            "determinante": self.determinante,
            "numero_condicao": cond if np.isfinite(cond) else None,
            "diagonal_dominante": self.diagonal_dominante,
            "mensagem": self.mensagem,
        }


@dataclass
class RiscoEquipamento:
    id: int
    hostname: str
    tipo: str
    fator_exposicao: float
    risco_bruto: float      # (M·v)_i  — soma dos CVSS, sem fator
    risco_proprio: float    # b_i
    risco_efetivo: float    # x_i
    risco_herdado: float    # x_i - b_i  (veio das dependências)

    def to_dict(self) -> dict:
        return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in self.__dict__.items()}


@dataclass
class ResultadoRisco:
    equipamentos: list[RiscoEquipamento]
    diagnostico: Diagnostico
    matrizes: dict = field(default_factory=dict)

    def por_id(self, id: int) -> RiscoEquipamento | None:
        return next((r for r in self.equipamentos if r.id == int(id)), None)

    def to_dict(self, incluir_matrizes: bool = False) -> dict:
        d = {
            "diagnostico": self.diagnostico.to_dict(),
            "equipamentos": [r.to_dict() for r in self.equipamentos],
        }
        if incluir_matrizes:
            d["matrizes"] = self.matrizes
        return d


class ModeloRisco:
    def __init__(self, M, v, A, fatores=None, ids=None, hostnames=None, tipos=None,
                 ids_vulnerabilidades=None):
        self.M = np.asarray(M, dtype=float)
        self.v = np.asarray(v, dtype=float)
        if self.M.ndim != 2:
            raise ValueError("M deve ser uma matriz (2 dimensões).")
        n = self.M.shape[0]
        self.A = np.asarray(A, dtype=float).reshape(n, n)
        self.fatores = np.ones(n) if fatores is None else np.asarray(fatores, dtype=float)
        self.ids = list(ids) if ids is not None else list(range(1, n + 1))
        self.hostnames = list(hostnames) if hostnames is not None else [f"E{i}" for i in self.ids]
        self.tipos = list(tipos) if tipos is not None else [""] * n
        self.ids_vulnerabilidades = (list(ids_vulnerabilidades) if ids_vulnerabilidades is not None
                                     else list(range(1, len(self.v) + 1)))

        if self.M.shape[1] != len(self.v):
            raise ValueError("M deve ter uma coluna para cada vulnerabilidade de v.")

    # ------------------------------------------------------------------
    # a) Montagem das matrizes a partir dos objetos persistidos
    # ------------------------------------------------------------------
    @classmethod
    def a_partir_do_inventario(cls, equipamentos, vulnerabilidades, dependencias) -> "ModeloRisco":
        n, m = len(equipamentos), len(vulnerabilidades)
        linha = {e.id: i for i, e in enumerate(equipamentos)}   # id do equipamento -> índice i

        M = np.zeros((n, m))
        v = np.zeros(m)
        for j, vul in enumerate(vulnerabilidades):
            v[j] = vul.cvss
            for id_eq in vul.equipamentos:
                if id_eq in linha:
                    M[linha[id_eq], j] = 1.0

        A = np.zeros((n, n))
        for d in dependencias:
            if d.dependente in linha and d.origem in linha:
                A[linha[d.dependente], linha[d.origem]] = d.fracao

        # Polimorfismo: cada objeto responde com o fator do SEU tipo.
        fatores = [e.fator_exposicao for e in equipamentos]

        return cls(M, v, A, fatores,
                   ids=[e.id for e in equipamentos],
                   hostnames=[e.hostname for e in equipamentos],
                   tipos=[e.DESCRICAO for e in equipamentos],
                   ids_vulnerabilidades=[vul.id for vul in vulnerabilidades])

    # ------------------------------------------------------------------
    # Risco próprio:  b = F · (M · v)
    # ------------------------------------------------------------------
    def risco_bruto(self) -> np.ndarray:
        """M·v — a transformação linear M leva o espaço das vulnerabilidades
        (R^m) ao espaço dos equipamentos (R^n)."""
        return self.M @ self.v

    def risco_proprio(self) -> np.ndarray:
        return self.fatores * self.risco_bruto()

    # ------------------------------------------------------------------
    # b) Verificação de invertibilidade de I - A
    # ------------------------------------------------------------------
    def diagnosticar(self) -> Diagnostico:
        n = self.A.shape[0]
        if n == 0:
            return Diagnostico(True, 1.0, 1.0, True, "Nenhum equipamento cadastrado.")

        I_menos_A = np.eye(n) - self.A
        det = float(np.linalg.det(I_menos_A))
        cond = float(np.linalg.cond(I_menos_A))

        # Critério teórico (Lévy–Desplanques): |diagonal| > soma |fora da diagonal|
        # em todas as linhas  =>  invertível.  Com A_ii = 0 isso equivale a
        # "soma de cada linha de A < 1".
        diag = np.abs(np.diag(I_menos_A))
        fora = np.abs(I_menos_A).sum(axis=1) - diag
        dominante = bool(np.all(diag > fora))

        # NÃO usamos `det == 0`: em ponto flutuante o det de uma matriz singular
        # quase nunca dá zero exato, e o tamanho do det depende da escala da
        # matriz (det(0.1·I_20) = 1e-20 e mesmo assim ela é perfeita).
        # O número de condição mede quantos dígitos se perdem na solução.
        if not np.isfinite(cond) or cond >= LIMITE_SINGULAR:
            return Diagnostico(False, det, cond, dominante,
                               "I - A é singular (ou numericamente singular): o sistema não "
                               "possui solução única. Revise as dependências cadastradas.")
        if cond > LIMITE_MAL_CONDICIONADO:
            digitos = int(np.log10(cond))
            msg = (f"I - A é invertível, porém MAL CONDICIONADA (cond ≈ {cond:.2e}): "
                   f"a solução pode perder cerca de {digitos} dígitos de precisão.")
        else:
            msg = f"I - A é invertível e bem condicionada (cond ≈ {cond:.4g})."
        return Diagnostico(True, det, cond, dominante, msg)

    # ------------------------------------------------------------------
    # c) Resolução do sistema (I - A)·x = b
    # ------------------------------------------------------------------
    def resolver(self) -> ResultadoRisco:
        diag = self.diagnosticar()
        if not diag.invertivel:
            raise SistemaNaoInvertivel(diag)

        n = self.A.shape[0]
        bruto = self.risco_bruto()
        b = self.risco_proprio()
        # np.linalg.solve usa decomposição LU — mais rápido e mais preciso
        # do que calcular inv(I - A) e multiplicar por b.
        x = np.linalg.solve(np.eye(n) - self.A, b) if n else np.zeros(0)

        linhas = [
            RiscoEquipamento(id=self.ids[i], hostname=self.hostnames[i], tipo=self.tipos[i],
                             fator_exposicao=float(self.fatores[i]),
                             risco_bruto=float(bruto[i]), risco_proprio=float(b[i]),
                             risco_efetivo=float(x[i]), risco_herdado=float(x[i] - b[i]))
            for i in range(n)
        ]
        matrizes = {
            "ordem_equipamentos": self.ids,
            "ordem_vulnerabilidades": self.ids_vulnerabilidades,
            "M": self.M.tolist(),
            "v": self.v.tolist(),
            "fatores": self.fatores.tolist(),
            "A": self.A.tolist(),
            "b": b.tolist(),
            "x": x.tolist(),
        }
        return ResultadoRisco(linhas, diag, matrizes)
