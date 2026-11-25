"""Telas de análise de risco, matrizes e simulação."""

import os
import subprocess
import sys

from rich.panel import Panel
from rich.text import Text

from apresentacao.tema import COR
from dominio.risco import AnalisadorRisco, simular_vulnerabilidade
from dominio.validacoes import validar_cvss


class TelasRisco:
    """Telas de análise de risco, matrizes e simulação."""

    def analise(self):
        if not self.inventario:
            self.aviso("Ainda não há ativos cadastrados.")
            return
        analisador = AnalisadorRisco(self.inventario.ativos)
        lista, m, v, b, a, x = analisador.calcular()
        linhas = []
        for i in sorted(range(len(lista)), key=lambda pos: (-x[pos], lista[pos].id)):
            ativo = lista[i]
            linhas.append(
                (
                    f"#{ativo.id} {ativo.nome}",
                    f"{b[i]:.2f}",
                    f"{analisador.herdado[i]:+.2f}",
                    f"{x[i]:.2f}",
                )
            )
        if (
            self.mostrar_lista(
                "Equipamentos por risco efetivo",
                ("Equipamento", "Próprio", "Herdado", "Efetivo"),
                linhas,
            )
            is False
        ):
            return False
        self.console.print(
            Panel(
                "b = F·Mv    |    x = b + Ax    |    (I-A)x = b\n"
                "M: incidência de CVE por ativo. v: notas CVSS. A: dependências. "
                "F: fator de exposição do tipo.\n"
                "[yellow]O risco calculado é um índice acadêmico, não uma nota CVSS.[/]",
                title="Modelo matemático da avaliação",
                border_style=COR,
            )
        )
        escolha = self.nav.escolha(
            "Detalhamento do modelo",
            [
                "Matrizes, vetores e verificação",
                "Explicar a conta de um equipamento",
                "Simular nova vulnerabilidade",
                "Voltar",
            ],
        )
        if escolha == 0:
            ids = [f"#{ativo.id}" for ativo in lista]
            cves = [vul.cve for vul in analisador.vulnerabilidades]
            for titulo, colunas, matriz in (
                ("M · incidência", cves, m),
                ("A · dependências", ids, a),
                ("S = I − A · sistema", ids, analisador.matriz_sistema),
            ):
                if self.exibir_matriz(titulo, ids, colunas, matriz) is False:
                    return False
            vetores = "\n".join(
                f"{rotulo} = ({', '.join(f'{valor:.6g}' for valor in valores)})"
                for rotulo, valores in (
                    ("v", v),
                    ("F", analisador.fatores),
                    ("b", b),
                    ("Ax", analisador.herdado),
                    ("x", x),
                )
            )
            diagnostico = (
                f"det(I − A) = {analisador.determinante:.6g}\n"
                f"κ∞(I − A) = {analisador.numero_condicao:.6g}\n"
                f"Maior soma de pesos de uma linha de A = {analisador.maior_soma_pesos:.8g}\n"
                f"Resíduo ||(I − A)x − b||∞ = {analisador.residuo:.3e}"
            )
            self.console.print(Panel(vetores + "\n\n" + diagnostico, title="Solução e verificação"))
        elif escolha == 1:
            ativo = self.escolher_ativo()
            i = lista.index(ativo)
            proprios = " + ".join(f"1 × {nota:.6g}" for incide, nota in zip(m[i], v) if incide)
            herdados = " + ".join(
                f"{peso:.6g} × {x[j]:.6g} (#{origem.id})"
                for j, (origem, peso) in enumerate(zip(lista, a[i]))
                if peso
            )
            conta = (
                f"Mv = {proprios or '0'} = {analisador.soma_cvss[i]:.6g}\n"
                f"b = F·Mv = {analisador.fatores[i]:.6g} × "
                f"{analisador.soma_cvss[i]:.6g} = {b[i]:.6g}\n"
                f"Ax = {herdados or '0'} = {analisador.herdado[i]:.6g}\n"
                f"x = b + Ax = {b[i]:.6g} + {analisador.herdado[i]:.6g} = {x[i]:.6g}"
            )
            self.console.print(
                Panel(
                    conta,
                    title=Text(f"Conta de #{ativo.id} · {ativo.nome}"),
                )
            )
        elif escolha == 2:
            return self.simulacao()
        else:
            return False

    def exibir_matriz(self, titulo, ids, colunas, matriz):
        if not colunas:
            self.aviso(f"{titulo} ({len(ids)} × 0). Sem vulnerabilidades cadastradas.")
            return
        largura = max(12, max(map(len, colunas)) + 3)
        por_bloco = max(1, (self.console.width - 10) // largura)
        ultima = (len(colunas) - 1) // por_bloco
        bloco = 0
        while True:
            inicio = bloco * por_bloco
            fim = min(inicio + por_bloco, len(colunas))
            linhas = [
                (identificador, *(f"{valor:.6g}" for valor in linha[inicio:fim]))
                for identificador, linha in zip(ids, matriz)
            ]
            dimensoes = f"{len(ids)} × {len(colunas)}"
            legenda = f"{titulo} ({dimensoes}) · colunas {inicio + 1}–{fim}"
            if self.mostrar_lista(legenda, ["Ativo", *colunas[inicio:fim]], linhas) is False:
                return False
            passos = self.passos_pagina(bloco, ultima)
            if not passos:
                return
            opcoes = list(passos) + ["Próxima matriz"]
            escolha = self.nav.menu("Colunas da matriz", opcoes)
            if escolha is None:
                return False
            if escolha == len(passos):
                return
            bloco += passos[opcoes[escolha]]

    def simulacao(self):
        ativo = self.escolher_ativo()
        cvss = self.nav.texto("Severidade CVSS hipotética", conversor=validar_cvss)
        lista, _, _, proprio_antigo, _, efetivo_antigo = AnalisadorRisco(
            self.inventario.ativos
        ).calcular()
        _, _, _, proprio_novo, _, efetivo_novo = simular_vulnerabilidade(
            self.inventario.ativos,
            ativo.id,
            cvss,
        )
        linhas = [
            (
                item.nome,
                f"{proprio_antigo[i]:.2f} → {proprio_novo[i]:.2f}",
                f"{efetivo_antigo[i]:.2f} → {efetivo_novo[i]:.2f}",
                f"{efetivo_novo[i] - efetivo_antigo[i]:+.2f}",
            )
            for i, item in enumerate(lista)
        ]
        return self.mostrar_lista(
            "Simulação temporária",
            ("Ativo", "Próprio", "Efetivo", "Variação"),
            linhas,
        )

    def diagnostico(self):
        pasta = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        resultado = subprocess.run(
            [sys.executable, "app.py", "--testes"],
            cwd=pasta,
            check=False,
        )
        if resultado.returncode:
            self.aviso("O Pytest não concluiu com sucesso. Veja a saída acima.", "red")
