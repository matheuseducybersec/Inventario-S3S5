"""
API HTTP (backend) — é o processo que roda continuamente dentro do container
(REQUISITO 3) e servirá de base para a aplicação web do trabalho final.

Documentação interativa gerada automaticamente: http://<host>:8000/docs
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .inventario import Inventario, NaoEncontrado
from .modelos import Equipamento, ErroValidacao
from .risco import SistemaNaoInvertivel

PASTA_DADOS = os.environ.get("INVENTARIO_DADOS", "data")
INICIO = datetime.now(timezone.utc)

# Uma escrita por vez nos arquivos JSON (o servidor atende requisições em threads).
_trava = threading.Lock()

app = FastAPI(
    title="Inventário de Ativos e Análise de Risco",
    description="Trabalho 2 — Cibersegurança/UFU. Equipamentos, vulnerabilidades, "
                "dependências e risco efetivo pelo modelo (I - A)x = b.",
    version="2.0.0",
)


def inventario() -> Inventario:
    """Recarrega do disco a cada requisição: a API não guarda estado em memória,
    então alterações feitas pela CLI (`docker exec`) aparecem imediatamente."""
    return Inventario(PASTA_DADOS)


# ---------------------------------------------------------------------
# Tratamento de erros do domínio -> códigos HTTP
# ---------------------------------------------------------------------
@app.exception_handler(ErroValidacao)
async def _erro_validacao(_: Request, exc: ErroValidacao):
    return JSONResponse(status_code=422, content={"erro": str(exc)})


@app.exception_handler(NaoEncontrado)
async def _nao_encontrado(_: Request, exc: NaoEncontrado):
    return JSONResponse(status_code=404, content={"erro": str(exc)})


@app.exception_handler(SistemaNaoInvertivel)
async def _singular(_: Request, exc: SistemaNaoInvertivel):
    return JSONResponse(status_code=409, content={"erro": str(exc),
                                                  "diagnostico": exc.diagnostico.to_dict()})


# ---------------------------------------------------------------------
# Esquemas de entrada (validados pelo Pydantic)
# ---------------------------------------------------------------------
class EquipamentoEntrada(BaseModel):
    tipo: str = Field(examples=["servidor"])
    hostname: str = Field(examples=["SRV-WEB-01"])
    responsavel: str = Field(examples=["Equipe de Infra"])
    setor: str = Field(examples=["Datacenter"])
    descricao: str = ""


class EquipamentoAtualizacao(BaseModel):
    tipo: str | None = None
    hostname: str | None = None
    responsavel: str | None = None
    setor: str | None = None
    descricao: str | None = None


class VulnerabilidadeEntrada(BaseModel):
    descricao: str = Field(examples=["SQL Injection no formulário de login"])
    cvss: float = Field(ge=0, le=10, examples=[9.8])
    categoria: str = ""
    status: str = "Aberta"
    equipamentos: list[int] = []


class StatusEntrada(BaseModel):
    status: str = Field(examples=["Corrigida"])


class DependenciaEntrada(BaseModel):
    dependente: int = Field(description="Equipamento que HERDA o risco (linha i de A)")
    origem: int = Field(description="Equipamento que TRANSMITE o risco (coluna j de A)")
    fracao: float = Field(ge=0, lt=1, examples=[0.3])


def _eq_saida(e: Equipamento) -> dict:
    return {**e.to_dict(), "tipo_descricao": e.DESCRICAO, "fator_exposicao": e.fator_exposicao}


# ---------------------------------------------------------------------
# Rotas
# ---------------------------------------------------------------------
@app.get("/health", tags=["sistema"])
def health():
    """Usado pelo HEALTHCHECK do Docker para saber se a aplicação está viva."""
    agora = datetime.now(timezone.utc)
    return {"status": "ok", "no_ar_desde": INICIO.isoformat(),
            "uptime_horas": round((agora - INICIO).total_seconds() / 3600, 3)}


@app.get("/tipos", tags=["equipamentos"])
def tipos():
    return [{"tipo": t, "descricao": c.DESCRICAO}
            for t, c in Equipamento.tipos_disponiveis().items()]


@app.get("/equipamentos", tags=["equipamentos"])
def listar_equipamentos(hostname: str | None = None):
    inv = inventario()
    lista = inv.buscar_por_hostname(hostname) if hostname else inv.listar_equipamentos()
    return [_eq_saida(e) for e in lista]


@app.get("/equipamentos/{id}", tags=["equipamentos"])
def obter_equipamento(id: int):
    inv = inventario()
    e = inv.obter_equipamento(id)
    return {**_eq_saida(e),
            "vulnerabilidades": [v.to_dict() for v in inv.vulnerabilidades_do_equipamento(id)]}


@app.post("/equipamentos", status_code=201, tags=["equipamentos"])
def criar_equipamento(dados: EquipamentoEntrada):
    with _trava:
        return _eq_saida(inventario().cadastrar_equipamento(**dados.model_dump()))


@app.put("/equipamentos/{id}", tags=["equipamentos"])
def atualizar_equipamento(id: int, dados: EquipamentoAtualizacao):
    with _trava:
        return _eq_saida(inventario().atualizar_equipamento(id, **dados.model_dump()))


@app.delete("/equipamentos/{id}", tags=["equipamentos"])
def remover_equipamento(id: int):
    with _trava:
        e = inventario().remover_equipamento(id)
    return {"removido": e.to_dict()}


@app.get("/vulnerabilidades", tags=["vulnerabilidades"])
def listar_vulnerabilidades():
    return [{**v.to_dict(), "severidade": v.severidade}
            for v in inventario().listar_vulnerabilidades()]


@app.post("/vulnerabilidades", status_code=201, tags=["vulnerabilidades"])
def criar_vulnerabilidade(dados: VulnerabilidadeEntrada):
    with _trava:
        return inventario().cadastrar_vulnerabilidade(**dados.model_dump()).to_dict()


@app.post("/vulnerabilidades/{id}/equipamentos/{id_equipamento}", tags=["vulnerabilidades"])
def associar(id: int, id_equipamento: int):
    with _trava:
        return inventario().associar(id, id_equipamento).to_dict()


@app.delete("/vulnerabilidades/{id}/equipamentos/{id_equipamento}", tags=["vulnerabilidades"])
def desassociar(id: int, id_equipamento: int):
    with _trava:
        return inventario().desassociar(id, id_equipamento).to_dict()


@app.patch("/vulnerabilidades/{id}/status", tags=["vulnerabilidades"])
def mudar_status(id: int, dados: StatusEntrada):
    with _trava:
        return inventario().atualizar_status_vulnerabilidade(id, dados.status).to_dict()


@app.delete("/vulnerabilidades/{id}", tags=["vulnerabilidades"])
def remover_vulnerabilidade(id: int):
    with _trava:
        return {"removida": inventario().remover_vulnerabilidade(id).to_dict()}


@app.get("/dependencias", tags=["dependências"])
def listar_dependencias():
    return [d.to_dict() for d in inventario().listar_dependencias()]


@app.put("/dependencias", tags=["dependências"])
def definir_dependencia(dados: DependenciaEntrada):
    with _trava:
        return inventario().definir_dependencia(**dados.model_dump()).to_dict()


@app.delete("/dependencias/{dependente}/{origem}", tags=["dependências"])
def remover_dependencia(dependente: int, origem: int):
    with _trava:
        return {"removida": inventario().remover_dependencia(dependente, origem).to_dict()}


@app.get("/risco", tags=["risco"])
def risco(matrizes: bool = False):
    """Risco próprio (b) e efetivo (x) de todos os equipamentos.
    Use `?matrizes=true` para ver M, v, A, b e x."""
    return inventario().calcular_risco().to_dict(incluir_matrizes=matrizes)


@app.get("/risco/{id}", tags=["risco"])
def risco_equipamento(id: int):
    inv = inventario()
    inv.obter_equipamento(id)  # 404 se não existir
    resultado = inv.calcular_risco()
    return {"diagnostico": resultado.diagnostico.to_dict(), **resultado.por_id(id).to_dict()}
