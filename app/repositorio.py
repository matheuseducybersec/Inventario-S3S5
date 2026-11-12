"""
Persistência em arquivo JSON.

REQUISITO 2 — cada arquivo é um ARRAY (lista) de objetos JSON, por exemplo:
    [
      {"id": 1, "tipo": "servidor", "hostname": "SRV-01", ...},
      {"id": 2, "tipo": "notebook", "hostname": "NB-07", ...}
    ]
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Callable, Generic, TypeVar

T = TypeVar("T")


class RepositorioJSON(Generic[T]):
    """
    Lê e grava uma lista de objetos em um arquivo JSON.

    Recebe a função que transforma dict -> objeto (`fabrica`), então a mesma
    classe serve para Equipamento, Vulnerabilidade e Dependencia.
    Todo objeto salvo precisa ter o método `to_dict()`.
    """

    def __init__(self, caminho: str | Path, fabrica: Callable[[dict], T]):
        self.caminho = Path(caminho)
        self.fabrica = fabrica

    def carregar(self) -> list[T]:
        if not self.caminho.exists():
            return []
        with open(self.caminho, "r", encoding="utf-8") as f:
            dados = json.load(f)
        if not isinstance(dados, list):
            raise ValueError(f"{self.caminho} deveria conter um array JSON.")
        return [self.fabrica(item) for item in dados]

    def salvar(self, objetos: list[T]) -> None:
        """
        Escrita ATÔMICA: grava num arquivo temporário e depois o renomeia.
        Se o container cair no meio da escrita, o arquivo antigo continua íntegro.
        """
        self.caminho.parent.mkdir(parents=True, exist_ok=True)
        dados = [obj.to_dict() for obj in objetos]
        fd, tmp = tempfile.mkstemp(dir=self.caminho.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(dados, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.caminho)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
