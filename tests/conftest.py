"""Configuração do relatório HTML gerado pelo pytest-html."""


def pytest_html_report_title(report):
    report.title = "Relatório de Testes — Inventário de Ativos e Análise de Risco"
