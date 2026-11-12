"""
Menu textual (continuação do Trabalho 1), agora orientado a objetos.

Execução local:        python -m app.cli
Dentro do container:   docker exec -it inventario python -m app.cli
"""

from __future__ import annotations

import os

import numpy as np

from .inventario import Inventario, NaoEncontrado
from .modelos import Equipamento, ErroValidacao, Vulnerabilidade
from .risco import SistemaNaoInvertivel


# ---------------------------------------------------------------------
# Entrada de dados com validação (mesma ideia do Trabalho 1)
# ---------------------------------------------------------------------
def pedir_texto(msg: str, obrigatorio: bool = True) -> str:
    while True:
        valor = input(msg).strip()
        if valor or not obrigatorio:
            return valor
        print("[Erro] Este campo não pode ficar vazio.")


def pedir_inteiro(msg: str) -> int:
    while True:
        try:
            return int(input(msg).strip())
        except ValueError:
            print("[Erro] Digite um número inteiro válido.")


def pedir_real(msg: str) -> float:
    while True:
        try:
            return float(input(msg).strip().replace(",", "."))
        except ValueError:
            print("[Erro] Digite um número válido (ex.: 7.5).")


def pedir_tipo() -> str:
    tipos = list(Equipamento.tipos_disponiveis().items())
    for i, (_, classe) in enumerate(tipos, start=1):
        print(f"  [{i}] {classe.DESCRICAO}")
    while True:
        n = pedir_inteiro("Tipo: ")
        if 1 <= n <= len(tipos):
            return tipos[n - 1][0]
        print("[Erro] Opção inválida.")


def linha():
    print("-" * 60)


# ---------------------------------------------------------------------
# Classe da interface: cada opção do menu é um método
# ---------------------------------------------------------------------
class MenuCLI:
    def __init__(self, inventario: Inventario):
        self.inv = inventario
        self.opcoes = {
            "1": ("Cadastrar equipamento", self.cadastrar_equipamento),
            "2": ("Consultar equipamento (ID ou hostname)", self.consultar_equipamento),
            "3": ("Listar equipamentos", self.listar_equipamentos),
            "4": ("Atualizar equipamento", self.atualizar_equipamento),
            "5": ("Remover equipamento", self.remover_equipamento),
            "6": ("Cadastrar vulnerabilidade", self.cadastrar_vulnerabilidade),
            "7": ("Associar vulnerabilidade a equipamento", self.associar),
            "8": ("Listar vulnerabilidades", self.listar_vulnerabilidades),
            "9": ("Alterar status de vulnerabilidade", self.alterar_status),
            "10": ("Definir dependência entre equipamentos", self.definir_dependencia),
            "11": ("Listar / remover dependências", self.dependencias),
            "12": ("Calcular risco (próprio e efetivo)", self.calcular_risco),
            "13": ("Mostrar matrizes do modelo (M, v, A, b, x)", self.mostrar_matrizes),
        }

    def executar(self):
        while True:
            print("\n" + "=" * 60)
            print("   INVENTÁRIO DE ATIVOS E ANÁLISE DE RISCO")
            print("=" * 60)
            for chave, (texto, _) in self.opcoes.items():
                print(f"{chave:>2} - {texto}")
            print(" 0 - Sair")
            opcao = input("Escolha: ").strip()
            if opcao == "0":
                print("Até logo!")
                return
            if opcao not in self.opcoes:
                print("[Erro] Opção inválida.")
                continue
            try:
                self.opcoes[opcao][1]()
            except (ErroValidacao, NaoEncontrado) as e:
                print(f"[Erro] {e}")
            except SistemaNaoInvertivel as e:
                print(f"[Risco] {e}")
                print(f"        det(I-A) = {e.diagnostico.determinante:.3e}  "
                      f"cond(I-A) = {e.diagnostico.numero_condicao:.3e}")

    # ---------------- equipamentos ----------------
    def _mostrar(self, e: Equipamento):
        linha()
        print(f"ID..........: {e.id}")
        print(f"Hostname....: {e.hostname}")
        print(f"Tipo........: {e.DESCRICAO}  (classe {type(e).__name__}, "
              f"fator de exposição {e.fator_exposicao})")
        print(f"Responsável.: {e.responsavel}")
        print(f"Setor.......: {e.setor}")
        if e.descricao:
            print(f"Descrição...: {e.descricao}")
        vuls = self.inv.vulnerabilidades_do_equipamento(e.id)
        print(f"Vulnerabilidades: {len(vuls)}")
        for v in vuls:
            print(f"   #{v.id} [{v.severidade} {v.cvss}] {v.descricao} ({v.status})")

    def cadastrar_equipamento(self):
        print("\n--- CADASTRAR EQUIPAMENTO ---")
        tipo = pedir_tipo()
        e = self.inv.cadastrar_equipamento(
            tipo=tipo,
            hostname=pedir_texto("Hostname: "),
            responsavel=pedir_texto("Responsável: "),
            setor=pedir_texto("Setor: "),
            descricao=pedir_texto("Descrição (opcional): ", obrigatorio=False),
        )
        print(f"[OK] {e!r} cadastrado.")

    def consultar_equipamento(self):
        termo = pedir_texto("ID ou parte do hostname: ")
        if termo.isdigit():
            self._mostrar(self.inv.obter_equipamento(int(termo)))
            return
        achados = self.inv.buscar_por_hostname(termo)
        if not achados:
            print("Nenhum equipamento encontrado.")
        for e in achados:
            self._mostrar(e)

    def listar_equipamentos(self):
        lista = self.inv.listar_equipamentos()
        if not lista:
            print("Nenhum equipamento cadastrado.")
        for e in lista:
            print(f"#{e.id:<3} {e.hostname:<20} {e.DESCRICAO:<20} {e.setor}")

    def atualizar_equipamento(self):
        e = self.inv.obter_equipamento(pedir_inteiro("ID: "))
        print("(ENTER mantém o valor atual)")
        campos = {c: input(f"{c} [{getattr(e, c)}]: ").strip()
                  for c in ("hostname", "responsavel", "setor", "descricao")}
        if input("Alterar o tipo? (s/N): ").strip().lower() == "s":
            campos["tipo"] = pedir_tipo()
        novo = self.inv.atualizar_equipamento(e.id, **campos)
        print(f"[OK] {novo!r} atualizado.")

    def remover_equipamento(self):
        e = self.inv.obter_equipamento(pedir_inteiro("ID: "))
        if input(f"Remover {e.hostname}? (s/N): ").strip().lower() == "s":
            self.inv.remover_equipamento(e.id)
            print("[OK] Removido (associações e dependências também).")

    # ---------------- vulnerabilidades ----------------
    def cadastrar_vulnerabilidade(self):
        print("\n--- CADASTRAR VULNERABILIDADE ---")
        descricao = pedir_texto("Descrição: ")
        categoria = pedir_texto("Categoria (opcional): ", obrigatorio=False)
        cvss = pedir_real("Nota CVSS (0 a 10): ")
        ids = pedir_texto("IDs dos equipamentos afetados (separados por vírgula, opcional): ",
                          obrigatorio=False)
        try:
            equipamentos = [int(x) for x in ids.replace(" ", "").split(",") if x]
        except ValueError:
            raise ErroValidacao("Lista de IDs inválida.") from None
        v = self.inv.cadastrar_vulnerabilidade(descricao, cvss, categoria,
                                               equipamentos=equipamentos)
        print(f"[OK] Vulnerabilidade #{v.id} ({v.severidade}) cadastrada.")

    def associar(self):
        v = self.inv.associar(pedir_inteiro("ID da vulnerabilidade: "),
                              pedir_inteiro("ID do equipamento: "))
        print(f"[OK] Vulnerabilidade #{v.id} afeta agora: {v.equipamentos}")

    def listar_vulnerabilidades(self):
        lista = self.inv.listar_vulnerabilidades()
        if not lista:
            print("Nenhuma vulnerabilidade cadastrada.")
        for v in lista:
            print(f"#{v.id:<3} CVSS {v.cvss:<4} {v.severidade:<8} {v.status:<18} "
                  f"equip. {v.equipamentos}  {v.descricao}")

    def alterar_status(self):
        vid = pedir_inteiro("ID da vulnerabilidade: ")
        print("Status: " + ", ".join(Vulnerabilidade.STATUS_VALIDOS))
        v = self.inv.atualizar_status_vulnerabilidade(vid, pedir_texto("Novo status: "))
        print(f"[OK] #{v.id} agora está '{v.status}'.")

    # ---------------- dependências ----------------
    def definir_dependencia(self):
        print("\nO equipamento DEPENDENTE herda uma fração do risco da ORIGEM.")
        d = self.inv.definir_dependencia(
            dependente=pedir_inteiro("ID do dependente (quem herda): "),
            origem=pedir_inteiro("ID da origem (de quem herda): "),
            fracao=pedir_real("Fração em [0, 1): "),
        )
        print(f"[OK] A[{d.dependente}][{d.origem}] = {d.fracao}")

    def dependencias(self):
        lista = self.inv.listar_dependencias()
        if not lista:
            print("Nenhuma dependência cadastrada.")
            return
        for d in lista:
            print(f"  {d.dependente} <- {d.origem}   fração {d.fracao}")
        if input("Remover alguma? (s/N): ").strip().lower() == "s":
            self.inv.remover_dependencia(pedir_inteiro("Dependente: "), pedir_inteiro("Origem: "))
            print("[OK] Removida.")

    # ---------------- risco ----------------
    def calcular_risco(self):
        r = self.inv.calcular_risco()
        print("\n" + r.diagnostico.mensagem)
        print(f"det(I-A) = {r.diagnostico.determinante:.6g}   "
              f"diagonal dominante: {'sim' if r.diagnostico.diagonal_dominante else 'não'}")
        linha()
        print(f"{'ID':<4}{'Hostname':<18}{'Fator':>6}{'Próprio (b)':>14}"
              f"{'Herdado':>10}{'Efetivo (x)':>14}")
        linha()
        for e in sorted(r.equipamentos, key=lambda e: -e.risco_efetivo):
            print(f"{e.id:<4}{e.hostname[:17]:<18}{e.fator_exposicao:>6.2f}"
                  f"{e.risco_proprio:>14.2f}{e.risco_herdado:>10.2f}{e.risco_efetivo:>14.2f}")

    def mostrar_matrizes(self):
        r = self.inv.calcular_risco()
        m = r.matrizes
        np.set_printoptions(precision=3, suppress=True)
        print(f"\nEquipamentos (linhas): {m['ordem_equipamentos']}")
        print(f"Vulnerabilidades (colunas): {m['ordem_vulnerabilidades']}")
        print(f"\nM =\n{np.array(m['M'])}")
        print(f"\nv = {np.array(m['v'])}")
        print(f"fatores = {np.array(m['fatores'])}")
        print(f"\nA =\n{np.array(m['A'])}")
        print(f"\nb = F·M·v = {np.array(m['b'])}")
        print(f"x = (I-A)^-1 b = {np.array(m['x'])}")


def main():
    MenuCLI(Inventario(os.environ.get("INVENTARIO_DADOS", "data"))).executar()


if __name__ == "__main__":
    main()
