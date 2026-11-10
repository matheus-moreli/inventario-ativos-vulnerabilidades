"""Painel de terminal para o CRUD, a rastreabilidade e a álgebra linear.

A interface antiga continua disponível em apresentacao.interface; esta camada
usa os mesmos objetos e as mesmas regras, sem duplicar cálculos.
"""
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm
from rich import box

from apresentacao.interface import InterfaceTerminal
from dominio.inventario import DadosInvalidosError
from dominio.risco import AnalisadorRisco, montar_matriz_incidencia
from infraestrutura.persistencia import RepositorioJSON


class InterfaceRica:
    def __init__(self, inventario, caminho_dados):
        self.inventario = inventario
        self.caminho_dados = caminho_dados
        self.console = Console()
        self.legado = InterfaceTerminal(inventario, caminho_dados)

    def salvar(self):
        if not RepositorioJSON(self.caminho_dados).salvar(self.inventario.ativos):
            raise DadosInvalidosError("Erro ao salvar. Confira as permissões do arquivo.")

    def cabecalho(self):
        c = self.console
        c.clear()
        c.print(Panel.fit(
            "[bold cyan]INVENTÁRIO DE SEGURANÇA[/]\n"
            "[dim]Ativos • CVE/CWE/CVSS • Dependências • Risco matemático[/]",
            border_style="cyan",
        ))
        ativos = list(self.inventario.values())
        qtd = sum(len(ativo.vulnerabilidades) for ativo in ativos)
        c.print(f"[green]Ativos: {len(ativos)}[/]   "
                f"[yellow]Vulnerabilidades: {qtd}[/]   "
                f"[dim]Porta HTTP: {os.environ.get('INVENTARIO_PORTA', '2217')}[/]\n")

    def pausar(self):
        Prompt.ask("[dim]Enter para continuar[/]", default="")

    def listar(self):
        tabela = Table(title="Equipamentos cadastrados", box=box.ROUNDED)
        for campo in ("ID", "Hostname", "Categoria", "Responsável", "Criticidade", "CVEs"):
            tabela.add_column(campo)
        for ativo in sorted(self.inventario.values(), key=lambda a: a.id):
            tabela.add_row(str(ativo.id), ativo.nome, ativo.nome_do_tipo(),
                           ativo.responsavel, ativo.criticidade,
                           str(len(ativo.vulnerabilidades)))
        self.console.print(tabela)
        if not len(self.inventario):
            self.console.print("[yellow]Nenhum equipamento cadastrado.[/]")

    def detalhes(self):
        identificador = IntPrompt.ask("ID do equipamento")
        ativo = self.inventario.consultar_por_id(identificador)
        if ativo is None:
            raise DadosInvalidosError("Ativo não encontrado.")
        self.console.print(Panel(
            f"[bold]{ativo.nome}[/]\n"
            f"ID: {ativo.id} | Tipo: {ativo.nome_do_tipo()} ({ativo.tipo})\n"
            f"Responsável: {ativo.responsavel}\n"
            f"Local: {ativo.localizacao}\n"
            f"Criticidade: {ativo.criticidade}",
            title="Ficha do equipamento",
        ))
        extras = Table(title="Campos personalizados", box=box.SIMPLE)
        extras.add_column("Campo")
        extras.add_column("Valor")
        for k, v in ativo.campos_extras.items():
            extras.add_row(k, v)
        self.console.print(extras)
        vulnerabilidades = Table(title="Vulnerabilidades", box=box.ROUNDED)
        for nome in ("CVE", "CWE", "CVSS", "Status", "Prioridade"):
            vulnerabilidades.add_column(nome)
        for v in ativo.vulnerabilidades:
            vulnerabilidades.add_row(v.cve, v.cwe, f"{v.cvss:.1f}",
                                     v.status, v.prioridade)
        self.console.print(vulnerabilidades)
        for d in ativo.dependencias:
            self.console.print(f"[dim]Depende do ativo {d['ativo_id']}: {d['peso']:.2f}[/]")
        if not ativo.vulnerabilidades:
            self.console.print("[green]Nenhuma vulnerabilidade registrada.[/]")

    def tipos(self):
        self.console.print(Panel(
            "\n".join(f"{codigo:>3}  {nome}" for codigo, nome
                      in self.inventario.listar_tipos().items()),
            title="Categorias disponíveis",
        ))
        if not Confirm.ask("Cadastrar equipamento com novo tipo?", default=False):
            return
        codigo = IntPrompt.ask("Código de tipo (100 ou superior)")
        if codigo < 100 or codigo in self.inventario.listar_tipos():
            raise DadosInvalidosError("Escolha um código novo, a partir de 100.")
        nome_tipo = Prompt.ask("Nome da categoria").strip()
        self.console.print("[dim]Cadastre o primeiro ativo dessa categoria:[/]")
        identificador = IntPrompt.ask("ID único")
        nome = Prompt.ask("Nome ou hostname")
        responsavel = Prompt.ask("Responsável")
        local = Prompt.ask("Localização")
        criticidade = Prompt.ask("Criticidade", choices=["Baixa", "Média", "Alta", "Crítica"])
        self.inventario.cadastrar_ativo(
            identificador, nome, responsavel, local, codigo, criticidade,
            nome_tipo_personalizado=nome_tipo,
        )
        self.salvar()
        self.console.print("[green]Tipo e equipamento cadastrados e persistidos.[/]")

    def metadados(self):
        identificador = IntPrompt.ask("ID do ativo")
        ativo = self.inventario.consultar_por_id(identificador)
        if ativo is None:
            raise DadosInvalidosError("Ativo não encontrado.")
        self.console.print(f"Campos existentes: {ativo.campos_extras}")
        acao = Prompt.ask("1-Adicionar/atualizar, 2-Remover, 0-Voltar",
                          choices=["1", "2", "0"], default="0")
        if acao == "0":
            return
        chave = Prompt.ask("Nome do campo").strip()
        if acao == "1":
            valor = Prompt.ask("Valor")
            self.inventario.definir_campo_extra(identificador, chave, valor)
        else:
            self.inventario.remover_campo_extra(identificador, chave)
        self.salvar()
        self.console.print("[green]Alteração salva no JSON.[/]")

    def analise(self):
        if not len(self.inventario):
            self.console.print("[yellow]Cadastre ativos para calcular os riscos.[/]")
            return
        analista = AnalisadorRisco(self.inventario.ativos)
        lista, m, v, b, a, x = analista.calcular()
        _, cves, _ = montar_matriz_incidencia(self.inventario.ativos)
        rotulos = [cve.cve for cve in cves]

        self.console.print(Panel(
            "M[i,j]=1 se o ativo i possui a CVE j.\n"
            "v contém as notas CVSS informadas.\n"
            "b = Mv (risco próprio)\n"
            "(I-A)x = b (risco efetivo por dependência)\n"
            "[yellow]O risco resultante NÃO é uma nota CVSS; pode superar 10.[/]",
            title="Método de cálculo",
        ))
        incid = Table(title=f"Matriz M ({len(lista)} × {len(v)})", box=box.SIMPLE)
        incid.add_column("Ativo")
        for label in rotulos:
            incid.add_column(label)
        for ativo, linha in zip(lista, m):
            incid.add_row(f"{ativo.id} {ativo.nome}", *(str(c) for c in linha))
        self.console.print(incid)
        self.console.print(f"[bold]Vetor v:[/] {v}")

        dep = Table(title=f"Matriz A ({len(lista)} × {len(lista)})", box=box.SIMPLE)
        dep.add_column("Ativo")
        for ativo in lista:
            dep.add_column(str(ativo.id))
        for ativo, linha in zip(lista, a):
            dep.add_row(str(ativo.id), *(f"{peso:.2f}" for peso in linha))
        self.console.print(dep)

        tabela = Table(title="Riscos calculados", box=box.ROUNDED)
        for coluna in ("ID", "Ativo", "Risco próprio (b)", "Risco efetivo (x)", "Herdado"):
            tabela.add_column(coluna)
        for i, ativo in enumerate(lista):
            tabela.add_row(str(ativo.id), ativo.nome, f"{b[i]:.2f}",
                           f"{x[i]:.2f}", f"{x[i] - b[i]:+.2f}")
        self.console.print(tabela)
        self.console.print(
            f"[green]I-A invertível[/] | número de condição (norma infinito): "
            f"{analista.numero_condicao:.3e}"
        )
        if analista.numero_condicao > 1e8:
            self.console.print("[yellow]Atenção: solução numericamente sensível.[/]")

    def diagnostico(self):
        from unittest import defaultTestLoader, TextTestRunner
        self.console.print("[cyan]Executando testes automáticos isolados...[/]")
        suite = defaultTestLoader.discover(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            pattern="test*.py",
        )
        resultado = TextTestRunner(verbosity=1).run(suite)
        estilo = "green" if resultado.wasSuccessful() else "red"
        self.console.print(Panel(
            f"Executados: {resultado.testsRun}\n"
            f"Falhas: {len(resultado.failures)}\n"
            f"Erros: {len(resultado.errors)}\n"
            f"Ignorados: {len(resultado.skipped)}",
            title=f"[{estilo}]Resultado dos testes[/{estilo}]",
        ))
        self.console.print("[dim]A prova de 24h deve ser verificada no Docker do docente.[/]")

    def executar(self):
        operacoes = {
            "1": ("Cadastrar ativo", self.legado.cadastrar_ativo_tela),
            "2": ("Listar ativos", self.listar),
            "3": ("Consultar ficha completa", self.detalhes),
            "4": ("Atualizar ativo", self.legado.atualizar_ativo_tela),
            "5": ("Excluir ativo", self.legado.remover_ativo_tela),
            "6": ("Cadastrar vulnerabilidade", self.legado.cadastrar_vulnerabilidade_tela),
            "7": ("Consultar vulnerabilidades", self.legado.consultar_vulnerabilidades_tela),
            "8": ("Atualizar vulnerabilidade", self.legado.atualizar_vulnerabilidade_tela),
            "9": ("Remover vulnerabilidade", self.legado.remover_vulnerabilidade_tela),
            "10": ("Resumo", self.legado.mostrar_resumo),
            "11": ("Dependências e simulação", self.legado.dependencias_e_riscos_tela),
            "12": ("Matrizes e riscos detalhados", self.analise),
            "13": ("Tipos personalizados", self.tipos),
            "14": ("Campos adicionais dos ativos", self.metadados),
            "15": ("Diagnóstico e testes", self.diagnostico),
        }
        while True:
            self.cabecalho()
            for chave, (nome, _) in operacoes.items():
                self.console.print(f"[cyan]{chave:>2}[/]  {nome}")
            self.console.print("[dim] 0  Sair[/]")
            escolha = Prompt.ask("\nEscolha", default="0")
            if escolha == "0":
                self.console.print("[green]Até a próxima.[/]")
                return
            if escolha not in operacoes:
                self.console.print("[red]Opção inválida.[/]")
                self.pausar()
                continue
            self.console.print(f"\n[bold cyan]{operacoes[escolha][0]}[/]\n")
            try:
                resultado = operacoes[escolha][1]()
                if escolha in {"1", "4", "5", "6", "8", "9", "11"} and resultado:
                    self.salvar()
                    self.console.print("[green]Dados persistidos.[/]")
            except (DadosInvalidosError, ValueError, KeyError) as erro:
                self.console.print(f"[red]Erro: {erro}[/]")
            self.pausar()
