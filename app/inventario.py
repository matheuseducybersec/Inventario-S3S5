"""
Camada de serviço: regras de negócio do inventário.

A CLI (menu) e a API web usam ESTA classe — nenhuma delas mexe direto no JSON.
Os objetos ficam em dicionários indexados por ID (hash map, acesso O(1)),
mantendo a ideia de otimização do Trabalho 1.
"""

from __future__ import annotations

from pathlib import Path

from .modelos import Dependencia, Equipamento, ErroValidacao, Vulnerabilidade
from .repositorio import RepositorioJSON
from .risco import ModeloRisco, ResultadoRisco


class NaoEncontrado(LookupError):
    """Lançado quando um ID não existe."""


class Inventario:
    def __init__(self, pasta_dados: str | Path = "data"):
        pasta = Path(pasta_dados)
        self._repo_eq = RepositorioJSON(pasta / "equipamentos.json", Equipamento.from_dict)
        self._repo_vul = RepositorioJSON(pasta / "vulnerabilidades.json", Vulnerabilidade.from_dict)
        self._repo_dep = RepositorioJSON(pasta / "dependencias.json", Dependencia.from_dict)

        self.equipamentos: dict[int, Equipamento] = {e.id: e for e in self._repo_eq.carregar()}
        self.vulnerabilidades: dict[int, Vulnerabilidade] = {v.id: v for v in self._repo_vul.carregar()}
        # chave (dependente, origem) -> Dependencia
        self.dependencias: dict[tuple[int, int], Dependencia] = {
            (d.dependente, d.origem): d for d in self._repo_dep.carregar()
        }

    # ------------------------------------------------------------------
    # utilitários internos
    # ------------------------------------------------------------------
    @staticmethod
    def _proximo_id(colecao: dict) -> int:
        return max(colecao, default=0) + 1

    def _salvar(self) -> None:
        self._repo_eq.salvar(sorted(self.equipamentos.values(), key=lambda e: e.id))
        self._repo_vul.salvar(sorted(self.vulnerabilidades.values(), key=lambda v: v.id))
        self._repo_dep.salvar(sorted(self.dependencias.values(),
                                     key=lambda d: (d.dependente, d.origem)))

    def _exigir_equipamento(self, id: int) -> Equipamento:
        try:
            return self.equipamentos[int(id)]
        except (KeyError, ValueError):
            raise NaoEncontrado(f"Equipamento {id} não encontrado.") from None

    def _exigir_vulnerabilidade(self, id: int) -> Vulnerabilidade:
        try:
            return self.vulnerabilidades[int(id)]
        except (KeyError, ValueError):
            raise NaoEncontrado(f"Vulnerabilidade {id} não encontrada.") from None

    # ------------------------------------------------------------------
    # EQUIPAMENTOS (CRUD)
    # ------------------------------------------------------------------
    def cadastrar_equipamento(self, tipo: str, hostname: str, responsavel: str,
                              setor: str, descricao: str = "") -> Equipamento:
        eq = Equipamento.criar(tipo, id=self._proximo_id(self.equipamentos),
                               hostname=hostname, responsavel=responsavel,
                               setor=setor, descricao=descricao)
        self.equipamentos[eq.id] = eq
        self._salvar()
        return eq

    def obter_equipamento(self, id: int) -> Equipamento:
        return self._exigir_equipamento(id)

    def listar_equipamentos(self) -> list[Equipamento]:
        return sorted(self.equipamentos.values(), key=lambda e: e.id)

    def buscar_por_hostname(self, trecho: str) -> list[Equipamento]:
        trecho = trecho.lower()
        return [e for e in self.listar_equipamentos() if trecho in e.hostname.lower()]

    def atualizar_equipamento(self, id: int, **campos) -> Equipamento:
        antigo = self._exigir_equipamento(id)
        dados = antigo.to_dict()
        dados.update({k: v for k, v in campos.items() if v not in (None, "")})
        # Recria o objeto: se o tipo mudou, a CLASSE do objeto também muda.
        novo = Equipamento.from_dict(dados)
        self.equipamentos[novo.id] = novo
        self._salvar()
        return novo

    def remover_equipamento(self, id: int) -> Equipamento:
        eq = self._exigir_equipamento(id)
        del self.equipamentos[eq.id]
        # Mantém a integridade: tira o equipamento das vulnerabilidades e
        # apaga as dependências em que ele aparece.
        for v in self.vulnerabilidades.values():
            if eq.id in v.equipamentos:
                v.equipamentos.remove(eq.id)
        self.dependencias = {k: d for k, d in self.dependencias.items() if eq.id not in k}
        self._salvar()
        return eq

    # ------------------------------------------------------------------
    # VULNERABILIDADES
    # ------------------------------------------------------------------
    def cadastrar_vulnerabilidade(self, descricao: str, cvss: float, categoria: str = "",
                                  status: str = "Aberta",
                                  equipamentos: list[int] | None = None) -> Vulnerabilidade:
        for e in equipamentos or []:
            self._exigir_equipamento(e)
        vul = Vulnerabilidade(id=self._proximo_id(self.vulnerabilidades), descricao=descricao,
                              cvss=cvss, categoria=categoria, status=status,
                              equipamentos=equipamentos)
        self.vulnerabilidades[vul.id] = vul
        self._salvar()
        return vul

    def obter_vulnerabilidade(self, id: int) -> Vulnerabilidade:
        return self._exigir_vulnerabilidade(id)

    def listar_vulnerabilidades(self) -> list[Vulnerabilidade]:
        return sorted(self.vulnerabilidades.values(), key=lambda v: v.id)

    def vulnerabilidades_do_equipamento(self, id_equipamento: int) -> list[Vulnerabilidade]:
        eq = self._exigir_equipamento(id_equipamento)
        return [v for v in self.listar_vulnerabilidades() if eq.id in v.equipamentos]

    def associar(self, id_vulnerabilidade: int, id_equipamento: int) -> Vulnerabilidade:
        vul = self._exigir_vulnerabilidade(id_vulnerabilidade)
        eq = self._exigir_equipamento(id_equipamento)
        if eq.id not in vul.equipamentos:
            vul.equipamentos = sorted(vul.equipamentos + [eq.id])
            self._salvar()
        return vul

    def desassociar(self, id_vulnerabilidade: int, id_equipamento: int) -> Vulnerabilidade:
        vul = self._exigir_vulnerabilidade(id_vulnerabilidade)
        if int(id_equipamento) in vul.equipamentos:
            vul.equipamentos.remove(int(id_equipamento))
            self._salvar()
        return vul

    def atualizar_status_vulnerabilidade(self, id: int, status: str) -> Vulnerabilidade:
        vul = self._exigir_vulnerabilidade(id)
        vul.status = status
        self._salvar()
        return vul

    def remover_vulnerabilidade(self, id: int) -> Vulnerabilidade:
        vul = self._exigir_vulnerabilidade(id)
        del self.vulnerabilidades[vul.id]
        self._salvar()
        return vul

    # ------------------------------------------------------------------
    # DEPENDÊNCIAS
    # ------------------------------------------------------------------
    def definir_dependencia(self, dependente: int, origem: int, fracao: float) -> Dependencia:
        """
        Cria/atualiza A[dependente][origem] = fracao.

        Regra imposta no cadastro (dica do enunciado): a soma de cada LINHA de A
        deve ficar < 1. Assim I - A é estritamente diagonal dominante e,
        portanto, sempre invertível.
        """
        self._exigir_equipamento(dependente)
        self._exigir_equipamento(origem)
        nova = Dependencia(dependente, origem, fracao)

        soma_linha = sum(d.fracao for (dep, ori), d in self.dependencias.items()
                         if dep == nova.dependente and ori != nova.origem) + nova.fracao
        if soma_linha >= 1.0:
            raise ErroValidacao(
                f"A soma das frações herdadas pelo equipamento {dependente} ficaria "
                f"{soma_linha:.3f} (precisa ser < 1). Isso garante que I - A seja invertível."
            )
        self.dependencias[(nova.dependente, nova.origem)] = nova
        self._salvar()
        return nova

    def remover_dependencia(self, dependente: int, origem: int) -> Dependencia:
        try:
            dep = self.dependencias.pop((int(dependente), int(origem)))
        except KeyError:
            raise NaoEncontrado("Dependência não encontrada.") from None
        self._salvar()
        return dep

    def listar_dependencias(self) -> list[Dependencia]:
        return sorted(self.dependencias.values(), key=lambda d: (d.dependente, d.origem))

    # ------------------------------------------------------------------
    # RISCO (REQUISITO 4)
    # ------------------------------------------------------------------
    def calcular_risco(self) -> ResultadoRisco:
        modelo = ModeloRisco.a_partir_do_inventario(
            self.listar_equipamentos(), self.listar_vulnerabilidades(), self.listar_dependencias()
        )
        return modelo.resolver()
