"""
Modelos de domínio (camada de objetos).

REQUISITO 1 — cada ativo é um OBJETO de uma classe derivada de `Equipamento`.

Recursos de orientação a objetos usados aqui:
  * Classe abstrata (ABC)  -> `Equipamento` não pode ser instanciada diretamente.
  * Herança                -> Notebook, Servidor, ... herdam de Equipamento.
  * Polimorfismo           -> cada subclasse define seu próprio `fator_exposicao`,
                              e o modelo de risco chama o mesmo atributo sem saber
                              qual é o tipo concreto do objeto.
  * Encapsulamento         -> validação dentro de properties (setters).
  * Métodos de classe      -> `from_dict` funciona como "fábrica" de objetos.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ErroValidacao(ValueError):
    """Erro lançado quando um dado não respeita as regras do domínio."""


def _texto_obrigatorio(valor, campo: str) -> str:
    texto = str(valor or "").strip()
    if not texto:
        raise ErroValidacao(f"O campo '{campo}' não pode ficar vazio.")
    return texto


# =====================================================================
# EQUIPAMENTOS
# =====================================================================
class Equipamento(ABC):
    """Classe base (abstrata) de todos os equipamentos do inventário."""

    # Registro automático de subclasses: {"servidor": Servidor, ...}.
    # Usado para recriar o objeto certo a partir do JSON.
    _tipos: dict[str, type["Equipamento"]] = {}

    TIPO: str = ""        # identificador gravado no JSON
    DESCRICAO: str = ""   # nome amigável

    def __init_subclass__(cls, **kwargs):
        """Executado automaticamente quando alguém cria uma subclasse."""
        super().__init_subclass__(**kwargs)
        if cls.TIPO:
            Equipamento._tipos[cls.TIPO] = cls

    def __init__(self, id: int, hostname: str, responsavel: str,
                 setor: str, descricao: str = ""):
        self.id = int(id)
        self.hostname = hostname
        self.responsavel = responsavel
        self.setor = setor
        self.descricao = (descricao or "").strip()

    # ---------- encapsulamento: validação via properties ----------
    @property
    def hostname(self) -> str:
        return self._hostname

    @hostname.setter
    def hostname(self, valor):
        self._hostname = _texto_obrigatorio(valor, "hostname")

    @property
    def responsavel(self) -> str:
        return self._responsavel

    @responsavel.setter
    def responsavel(self, valor):
        self._responsavel = _texto_obrigatorio(valor, "responsavel")

    @property
    def setor(self) -> str:
        return self._setor

    @setor.setter
    def setor(self, valor):
        self._setor = _texto_obrigatorio(valor, "setor")

    # ---------- polimorfismo ----------
    @property
    @abstractmethod
    def fator_exposicao(self) -> float:
        """Peso aplicado ao risco próprio. Cada tipo define o seu."""

    # ---------- serialização ----------
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tipo": self.TIPO,
            "hostname": self.hostname,
            "responsavel": self.responsavel,
            "setor": self.setor,
            "descricao": self.descricao,
        }

    @classmethod
    def tipos_disponiveis(cls) -> dict[str, type["Equipamento"]]:
        return dict(cls._tipos)

    @classmethod
    def criar(cls, tipo: str, **dados) -> "Equipamento":
        """Fábrica: escolhe a subclasse certa pelo campo 'tipo'."""
        subclasse = cls._tipos.get(tipo)
        if subclasse is None:
            validos = ", ".join(cls._tipos)
            raise ErroValidacao(f"Tipo '{tipo}' inválido. Use um destes: {validos}.")
        return subclasse(**dados)

    @classmethod
    def from_dict(cls, dados: dict) -> "Equipamento":
        dados = dict(dados)
        tipo = dados.pop("tipo")
        return cls.criar(tipo, **dados)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(id={self.id}, hostname={self.hostname!r})"


# ---- Subclasses: cada uma sobrescreve o fator de exposição ----
# Fator > 1  -> equipamento mais exposto (ex.: voltado para a internet).
# Fator < 1  -> equipamento menos exposto / menos crítico.
class Notebook(Equipamento):
    TIPO, DESCRICAO = "notebook", "Notebook"

    @property
    def fator_exposicao(self) -> float:
        return 0.8   # uso individual, geralmente atrás de firewall


class Servidor(Equipamento):
    TIPO, DESCRICAO = "servidor", "Servidor"

    @property
    def fator_exposicao(self) -> float:
        return 1.0   # referência


class Roteador(Equipamento):
    TIPO, DESCRICAO = "roteador", "Roteador"

    @property
    def fator_exposicao(self) -> float:
        return 1.1   # borda da rede, controla o tráfego


class AplicacaoWeb(Equipamento):
    TIPO, DESCRICAO = "aplicacao_web", "Aplicação Web"

    @property
    def fator_exposicao(self) -> float:
        return 1.2   # exposta diretamente à internet


class BancoDeDados(Equipamento):
    TIPO, DESCRICAO = "banco_de_dados", "Banco de Dados"

    @property
    def fator_exposicao(self) -> float:
        return 1.0   # interno, mas guarda dados sensíveis


class ImpressoraRede(Equipamento):
    TIPO, DESCRICAO = "impressora", "Impressora de Rede"

    @property
    def fator_exposicao(self) -> float:
        return 0.5   # baixo impacto


# =====================================================================
# VULNERABILIDADE
# =====================================================================
class Vulnerabilidade:
    """Uma vulnerabilidade pode afetar VÁRIOS equipamentos (relação N:N)."""

    STATUS_VALIDOS = ("Aberta", "Em tratamento", "Corrigida", "Aceita como risco")

    def __init__(self, id: int, descricao: str, cvss: float,
                 categoria: str = "", status: str = "Aberta",
                 equipamentos: list[int] | None = None):
        self.id = int(id)
        self.descricao = _texto_obrigatorio(descricao, "descricao")
        self.categoria = (categoria or "").strip()
        self.cvss = cvss
        self.status = status
        self.equipamentos: list[int] = sorted({int(e) for e in (equipamentos or [])})

    @property
    def cvss(self) -> float:
        return self._cvss

    @cvss.setter
    def cvss(self, valor):
        try:
            valor = float(valor)
        except (TypeError, ValueError):
            raise ErroValidacao("A nota CVSS deve ser um número.") from None
        if not 0.0 <= valor <= 10.0:
            raise ErroValidacao("A nota CVSS deve estar entre 0.0 e 10.0.")
        self._cvss = valor

    @property
    def status(self) -> str:
        return self._status

    @status.setter
    def status(self, valor):
        for s in self.STATUS_VALIDOS:
            if str(valor).strip().lower() == s.lower():
                self._status = s
                return
        raise ErroValidacao(f"Status inválido. Use: {', '.join(self.STATUS_VALIDOS)}.")

    @property
    def severidade(self) -> str:
        """Faixas qualitativas oficiais do CVSS v3."""
        if self.cvss == 0:
            return "Nenhuma"
        if self.cvss < 4:
            return "Baixa"
        if self.cvss < 7:
            return "Média"
        if self.cvss < 9:
            return "Alta"
        return "Crítica"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "descricao": self.descricao,
            "categoria": self.categoria,
            "cvss": self.cvss,
            "status": self.status,
            "equipamentos": self.equipamentos,
        }

    @classmethod
    def from_dict(cls, dados: dict) -> "Vulnerabilidade":
        return cls(**dados)


# =====================================================================
# DEPENDÊNCIA ENTRE EQUIPAMENTOS
# =====================================================================
class Dependencia:
    """
    `dependente` depende de `origem`: uma fração `fracao` do risco da origem
    é transmitida ao dependente. Na matriz A isso vira:
        A[dependente][origem] = fracao
    """

    def __init__(self, dependente: int, origem: int, fracao: float):
        self.dependente = int(dependente)
        self.origem = int(origem)
        if self.dependente == self.origem:
            raise ErroValidacao("Um equipamento não pode depender de si mesmo (A_ii = 0).")
        try:
            fracao = float(fracao)
        except (TypeError, ValueError):
            raise ErroValidacao("A fração deve ser um número.") from None
        if not 0.0 <= fracao < 1.0:
            raise ErroValidacao("A fração deve estar no intervalo [0, 1).")
        self.fracao = fracao

    def to_dict(self) -> dict:
        return {"dependente": self.dependente, "origem": self.origem, "fracao": self.fracao}

    @classmethod
    def from_dict(cls, dados: dict) -> "Dependencia":
        return cls(**dados)
