"""
Carrega o cenário de validação (3 equipamentos) resolvido à mão no README.

    python -m app.demo            (só carrega se a base estiver vazia)
    python -m app.demo --forcar   (apaga a base e recarrega)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .inventario import Inventario


def carregar_demo(pasta: str | Path, forcar: bool = False) -> Inventario:
    pasta = Path(pasta)
    if forcar:
        for nome in ("equipamentos.json", "vulnerabilidades.json", "dependencias.json"):
            (pasta / nome).unlink(missing_ok=True)

    inv = Inventario(pasta)
    if inv.equipamentos:
        print("A base já tem dados; nada foi alterado (use --forcar para recriar).")
        return inv

    web = inv.cadastrar_equipamento("aplicacao_web", "APP-PORTAL", "Equipe Web", "DMZ",
                                    "Portal do aluno")
    bd = inv.cadastrar_equipamento("banco_de_dados", "DB-ACADEMICO", "DBA", "Datacenter",
                                   "PostgreSQL com notas e matrículas")
    nb = inv.cadastrar_equipamento("notebook", "NB-SECRETARIA", "Maria", "Secretaria",
                                   "Notebook que acessa o portal")

    inv.cadastrar_vulnerabilidade("Framework web desatualizado (RCE)", 8.0, "Software",
                                  equipamentos=[web.id])
    inv.cadastrar_vulnerabilidade("Credencial padrão compartilhada", 6.0, "Configuração",
                                  equipamentos=[web.id, bd.id])
    inv.cadastrar_vulnerabilidade("Sistema operacional sem patch", 5.0, "Software",
                                  equipamentos=[nb.id])

    inv.definir_dependencia(dependente=web.id, origem=bd.id, fracao=0.5)
    inv.definir_dependencia(dependente=bd.id, origem=web.id, fracao=0.2)
    inv.definir_dependencia(dependente=nb.id, origem=web.id, fracao=0.1)
    print("Cenário de demonstração carregado.")
    return inv


if __name__ == "__main__":
    carregar_demo(os.environ.get("INVENTARIO_DADOS", "data"), forcar="--forcar" in sys.argv)
