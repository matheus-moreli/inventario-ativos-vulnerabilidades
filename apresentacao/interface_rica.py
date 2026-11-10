"""Interface única de terminal, com navegação por setas e operações reversíveis.

Não chama a interface antiga. Valida e persiste cada operação em um rascunho:
Esc/Ctrl+C em qualquer campo cancela o fluxo sem alterações parciais no JSON.
"""
from copy import deepcopy
import os
import unittest

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apresentacao.navegacao import Navegacao, OperacaoCancelada
from dominio.inventario import (
    DadosInvalidosError, Inventario, validar_cvss, validar_cve,
    validar_cwe, validar_data_fonte,
)
from dominio.modelos import CRITICIDADES, SEVERIDADES, STATUS
from dominio.risco import AnalisadorRisco, montar_matriz_incidencia, simular_vulnerabilidade
from infraestrutura.persistencia import RepositorioJSON


COR = "bright_cyan"


class InterfaceRica:
    """Mesmo padrão visual e de interação para todas as funções do inventário."""

    def __init__(self, inventario, caminho_dados, navegacao=None, console=None):
        self.inventario = (
            inventario if isinstance(inventario, Inventario) else Inventario(inventario)
        )
        self.caminho_dados = caminho_dados
        self.nav = navegacao or Navegacao()
        self.console = console or Console()

    def cabecalho(self, titulo="Painel geral"):
        c = self.console
        c.clear()
        c.print(Panel(
            Text("INVENTÁRIO DE SEGURANÇA", style="bold bright_cyan")
            + Text("\nAtivos  •  Vulnerabilidades  •  Análise de riscos", style="dim"),
            title="UFU  |  Cibersegurança",
            border_style=COR,
            expand=True,
        ))
        ativos = list(self.inventario.values())
        qtd_cve = sum(len(ativo.vulnerabilidades) for ativo in ativos)
        try:
            analisador = AnalisadorRisco(self.inventario.ativos)
            _, _, _, proprio, _, efetivo = analisador.calcular()
            resumo = (
                f"Índice próprio: {sum(proprio):.2f}  |  "
                f"Índice efetivo: {sum(efetivo):.2f}"
            )
        except (ValueError, KeyError, ZeroDivisionError) as erro:
            resumo = f"Cálculo indisponível: {erro}"
        c.print(
            f"[bold]{len(ativos)}[/] ativos   |   "
            f"[bold]{qtd_cve}[/] registros de vulnerabilidade   |   "
            f"[dim]{resumo}[/]"
        )
        c.rule(f"[bold {COR}]{titulo}[/]")

    def aviso(self, mensagem, estilo="yellow"):
        self.console.print(Panel(mensagem, border_style=estilo, expand=False))

    def pausar(self):
        try:
            self.nav.texto("Enter para continuar", obrigatorio=False)
        except OperacaoCancelada:
            pass

    def executar_tela(self, titulo, acoes):
        """Um único fluxo de submenus. Esc sempre volta à tela anterior."""
        while True:
            self.cabecalho(titulo)
            indice = self.nav.menu(titulo, [nome for nome, _ in acoes])
            if indice is None:
                return
            try:
                acoes[indice][1]()
            except OperacaoCancelada:
                self.aviso("Operação cancelada. Nenhuma alteração foi salva.", "yellow")
            except (DadosInvalidosError, ValueError, KeyError, OSError) as erro:
                self.aviso(f"Não foi possível concluir: {erro}", "red")
            self.pausar()

    def transacao(self, modificar, confirmar=True, perigosa=False):
        """Só publica no objeto vivo após validar e gravar o rascunho."""
        rascunho = Inventario(deepcopy(self.inventario.ativos))
        modificar(rascunho)
        # Reconstrói M, v e A com os dados atualizados antes de persistir.
        AnalisadorRisco(rascunho.ativos).calcular()
        if confirmar and not self.nav.confirmar(
            "Salvar as alterações?", risco=perigosa
        ):
            raise OperacaoCancelada()
        if not RepositorioJSON(self.caminho_dados).salvar(rascunho.ativos):
            raise DadosInvalidosError("Falha na gravação: dados anteriores preservados.")
        self.inventario._ativos = rascunho.ativos
        self.aviso(
            "Alteração salva. Matrizes e indicadores de risco recalculados.",
            "green",
        )

    def escolher_ativo(self, inventario=None, mensagem="Selecione o ativo"):
        """Paginador para inventários maiores que uma tela."""
        inventario = inventario or self.inventario
        ativos = sorted(inventario.values(), key=lambda item: item.id)
        if not ativos:
            raise DadosInvalidosError("Ainda não há ativos cadastrados.")
        pagina = 0
        while True:
            trecho = ativos[pagina * 10:(pagina + 1) * 10]
            opcoes = [
                f"#{ativo.id:<5} {ativo.nome[:32]:<32} {ativo.nome_do_tipo()}"
                for ativo in trecho
            ]
            if pagina > 0:
                opcoes.append("← Página anterior")
            if (pagina + 1) * 10 < len(ativos):
                opcoes.append("→ Próxima página")
            escolha = self.nav.escolha(mensagem, opcoes)
            if escolha < len(trecho):
                return trecho[escolha]
            if opcoes[escolha].startswith("←"):
                pagina -= 1
            else:
                pagina += 1

    def escolher_vulnerabilidade(self, inventario=None):
        inventario = inventario or self.inventario
        registros = inventario.consultar_vulnerabilidades()
        if not registros:
            raise DadosInvalidosError("Nenhuma vulnerabilidade cadastrada.")
        pagina = 0
        while True:
            trecho = registros[pagina * 10:(pagina + 1) * 10]
            opcoes = [
                f"{v.cve}  |  #{ativo.id} {ativo.nome[:24]}  |  CVSS {v.cvss:.1f}"
                for ativo, v in trecho
            ]
            if pagina > 0:
                opcoes.append("← Página anterior")
            if (pagina + 1) * 10 < len(registros):
                opcoes.append("→ Próxima página")
            escolha = self.nav.escolha("Escolha a vulnerabilidade", opcoes)
            if escolha < len(trecho):
                return trecho[escolha]
            if opcoes[escolha].startswith("←"):
                pagina -= 1
            else:
                pagina += 1

    def escolher_opcao(self, titulo, valores, atual=None):
        indice = valores.index(atual) if atual in valores else 0
        return valores[self.nav.escolha(titulo, valores, indice)]

    def escolher_tipo(self, inventario):
        tipos = inventario.listar_tipos()
        codigos = list(tipos)
        escolhas = [f"{codigo:>3}  {tipos[codigo]}" for codigo in codigos]
        escolhas.append("+ Criar categoria personalizada")
        indice = self.nav.escolha("Categoria do ativo", escolhas)
        if indice < len(codigos):
            tipo = codigos[indice]
            return tipo, tipos[tipo] if tipo >= 100 else None
        codigo = self.nav.inteiro("Novo código de categoria (a partir de 100)")
        if codigo < 100 or codigo in tipos:
            raise DadosInvalidosError(
                "Código personalizado deve ser novo e maior ou igual a 100."
            )
        nome = self.nav.texto("Nome da categoria")
        return codigo, nome

    def listar_ativos(self):
        tabela = Table(box=box.ROUNDED, expand=True, header_style=COR)
        for titulo in ("ID", "Hostname", "Tipo", "Responsável", "Criticidade", "CVEs"):
            tabela.add_column(titulo)
        for ativo in sorted(self.inventario.values(), key=lambda a: a.id):
            tabela.add_row(
                str(ativo.id), ativo.nome, ativo.nome_do_tipo(),
                ativo.responsavel, ativo.criticidade,
                str(len(ativo.vulnerabilidades)),
            )
        self.console.print(tabela)
        if not len(self.inventario):
            self.aviso("Nenhum ativo cadastrado.")

    def mostrar_ficha(self):
        ativo = self.escolher_ativo()
        self.console.print(Panel(
            f"[bold]{ativo.nome}[/]\n"
            f"ID: {ativo.id}     Tipo: {ativo.nome_do_tipo()} ({ativo.tipo})\n"
            f"Responsável: {ativo.responsavel}\n"
            f"Localização: {ativo.localizacao}\n"
            f"Criticidade: {ativo.criticidade}",
            title="Identificação do equipamento",
            border_style=COR,
        ))
        if ativo.campos_extras:
            tabela = Table(title="Campos adicionais", box=box.SIMPLE)
            tabela.add_column("Campo")
            tabela.add_column("Conteúdo")
            for chave, valor in ativo.campos_extras.items():
                tabela.add_row(chave, valor)
            self.console.print(tabela)
        else:
            self.console.print("[dim]Sem campos adicionais.[/]")
        tabela = Table(title="Vulnerabilidades associadas", box=box.ROUNDED)
        for nome in ("CVE", "CWE", "CVSS", "Status", "Prioridade"):
            tabela.add_column(nome)
        for v in ativo.vulnerabilidades:
            tabela.add_row(v.cve, v.cwe, f"{v.cvss:.1f}", v.status, v.prioridade)
        self.console.print(tabela)
        if not ativo.vulnerabilidades:
            self.console.print("[green]Nenhuma vulnerabilidade registrada.[/]")
        if ativo.dependencias:
            self.console.print("[bold]Dependências:[/]")
            for dep in ativo.dependencias:
                self.console.print(
                    f"  • #{dep['ativo_id']}  |  peso {dep['peso']:.2f}"
                )
        self.console.print("[bold]Histórico:[/]")
        for linha in ativo.historico[-8:]:
            self.console.print(f"  [dim]{linha}[/]")

    def coletar_vulnerabilidade(self, inv, id_ativo):
        """Formulário único para a inclusão inicial ou posterior da CVE."""
        cve = self.nav.texto("CVE (CVE-AAAA-NÚMERO)", conversor=validar_cve)
        cwe = self.nav.texto("CWE (CWE-NÚMERO)", conversor=validar_cwe)
        cvss = self.nav.texto("Nota CVSS (0 a 10)", conversor=validar_cvss)
        descricao = self.nav.texto("Descrição da falha")
        fonte = self.nav.texto("Fonte consultada (ex.: NVD)")
        data = self.nav.texto("Data da fonte (DD/MM/AAAA)", conversor=validar_data_fonte)
        impacto = self.nav.texto("Impacto no ativo")
        prioridade = self.escolher_opcao("Prioridade de tratamento", SEVERIDADES)
        tratamento = self.nav.texto("Tratamento planejado")
        status = self.escolher_opcao("Situação atual", STATUS)
        verificacao = self.nav.texto(
            "Como a correção será verificada",
            padrao="Pendente" if status != "Corrigida" else None,
        )
        inv.cadastrar_vulnerabilidade(
            id_ativo, cve, cwe, cvss, descricao, fonte, data, impacto,
            prioridade, tratamento, status, verificacao,
        )

    def novo_ativo(self):
        def preparar(inv):
            identificador = self.nav.inteiro("ID único")
            nome = self.nav.texto("Nome ou hostname")
            responsavel = self.nav.texto("Responsável")
            localizacao = self.nav.texto("Localização")
            tipo, nome_tipo = self.escolher_tipo(inv)
            criticidade = self.escolher_opcao("Criticidade do ativo", CRITICIDADES)
            inv.cadastrar_ativo(
                identificador, nome, responsavel, localizacao,
                tipo, criticidade, nome_tipo_personalizado=nome_tipo,
            )
            while self.nav.confirmar("Adicionar campo personalizado agora?", risco=True):
                chave = self.nav.texto("Nome do campo adicional")
                valor = self.nav.texto("Valor do campo", obrigatorio=False)
                inv.definir_campo_extra(identificador, chave, valor)
            while self.nav.confirmar("Cadastrar vulnerabilidade inicial?", risco=True):
                self.coletar_vulnerabilidade(inv, identificador)
        self.transacao(preparar)

    def atualizar_ativo(self):
        ativo = self.escolher_ativo()
        def preparar(inv):
            while True:
                atual = inv.consultar_por_id(ativo.id)
                opcoes = [
                    "Nome / hostname", "Responsável", "Localização", "Categoria",
                    "Criticidade", "Salvar alterações",
                ]
                escolha = self.nav.escolha("Editar equipamento", opcoes)
                if escolha == 5:
                    return
                if escolha == 0:
                    inv.atualizar_ativo(ativo.id, nome=self.nav.texto(
                        "Hostname", padrao=atual.nome))
                elif escolha == 1:
                    inv.atualizar_ativo(ativo.id, responsavel=self.nav.texto(
                        "Responsável", padrao=atual.responsavel))
                elif escolha == 2:
                    inv.atualizar_ativo(ativo.id, localizacao=self.nav.texto(
                        "Localização", padrao=atual.localizacao))
                elif escolha == 3:
                    tipo, nome_tipo = self.escolher_tipo(inv)
                    inv.atualizar_ativo(
                        ativo.id, tipo=tipo, nome_tipo_personalizado=nome_tipo)
                elif escolha == 4:
                    inv.atualizar_ativo(ativo.id, criticidade=self.escolher_opcao(
                        "Criticidade", CRITICIDADES, atual.criticidade))
        self.transacao(preparar)

    def remover_ativo(self):
        ativo = self.escolher_ativo()
        if not self.nav.confirmar(
            f"Excluir #{ativo.id} e TODAS as suas vulnerabilidades?", risco=True
        ):
            raise OperacaoCancelada()
        self.transacao(
            lambda inv: inv.excluir_ativo(ativo.id, True),
            confirmar=False,
        )

    def campos_adicionais(self):
        ativo = self.escolher_ativo()
        acao = self.nav.escolha(
            f"Campos de #{ativo.id}: {ativo.nome}",
            ["Adicionar / atualizar campo", "Remover campo"],
        )
        chave = self.nav.texto("Nome do campo")
        if acao == 0:
            valor = self.nav.texto("Valor", obrigatorio=False)
            self.transacao(
                lambda inv: inv.definir_campo_extra(ativo.id, chave, valor)
            )
        else:
            self.transacao(
                lambda inv: inv.remover_campo_extra(ativo.id, chave)
            )

    def ver_categorias(self):
        tabela = Table(title="Tipos de equipamentos", box=box.ROUNDED)
        tabela.add_column("Código", justify="right")
        tabela.add_column("Categoria")
        for codigo, nome in self.inventario.listar_tipos().items():
            tabela.add_row(str(codigo), nome)
        self.console.print(tabela)
        self.console.print(
            "[dim]Novas categorias podem ser criadas no cadastro de ativos. "
            "Cada categoria personalizada usa código inteiro >= 100.[/]"
        )

    def listar_vulnerabilidades(self):
        tabela = Table(box=box.ROUNDED, expand=True, header_style=COR)
        for titulo in ("Ativo", "CVE", "CWE", "CVSS", "Prioridade", "Status"):
            tabela.add_column(titulo)
        for ativo, vul in self.inventario.consultar_vulnerabilidades():
            tabela.add_row(
                ativo.nome, vul.cve, vul.cwe, f"{vul.cvss:.1f}",
                vul.prioridade, vul.status,
            )
        self.console.print(tabela)
        if not self.inventario.consultar_vulnerabilidades():
            self.aviso("Nenhuma vulnerabilidade cadastrada.")

    def ficha_vulnerabilidade(self):
        ativo, vul = self.escolher_vulnerabilidade()
        tabela = Table(box=box.SIMPLE, show_header=False)
        tabela.add_column("Campo", style="bold cyan")
        tabela.add_column("Valor")
        campos = [
            ("Ativo", f"#{ativo.id} {ativo.nome}"),
            ("CVE", vul.cve), ("CWE", vul.cwe), ("CVSS", f"{vul.cvss:.1f}"),
            ("Descrição", vul.descricao), ("Fonte", vul.fonte),
            ("Data", vul.data_fonte), ("Impacto", vul.impacto),
            ("Prioridade", vul.prioridade), ("Tratamento", vul.tratamento),
            ("Status", vul.status), ("Verificação", vul.verificacao),
        ]
        for campo, valor in campos:
            tabela.add_row(campo, valor)
        self.console.print(Panel(tabela, title="Ficha da vulnerabilidade"))

    def nova_vulnerabilidade(self):
        ativo = self.escolher_ativo()
        self.transacao(
            lambda inv: self.coletar_vulnerabilidade(inv, ativo.id)
        )

    def atualizar_vulnerabilidade(self):
        ativo, vul = self.escolher_vulnerabilidade()

        def preparar(inv):
            while True:
                atual = inv.consultar_por_id(ativo.id).buscar_vulnerabilidade(vul.cve)
                opcoes = [
                    "Descrição", "Prioridade", "Tratamento", "Status",
                    "Verificação", "Salvar alterações",
                ]
                escolha = self.nav.escolha("Editar vulnerabilidade", opcoes)
                if escolha == 5:
                    return
                if escolha == 0:
                    inv.atualizar_vulnerabilidade(
                        ativo.id, vul.cve,
                        descricao=self.nav.texto("Descrição", padrao=atual.descricao),
                    )
                elif escolha == 1:
                    inv.atualizar_vulnerabilidade(
                        ativo.id, vul.cve,
                        prioridade=self.escolher_opcao(
                            "Prioridade", SEVERIDADES, atual.prioridade),
                    )
                elif escolha == 2:
                    inv.atualizar_vulnerabilidade(
                        ativo.id, vul.cve,
                        tratamento=self.nav.texto(
                            "Tratamento", padrao=atual.tratamento),
                    )
                elif escolha == 3:
                    novo_status = self.escolher_opcao(
                        "Status", STATUS, atual.status)
                    nova_verificacao = None
                    if (novo_status == "Corrigida"
                            and atual.verificacao.lower() == "pendente"):
                        nova_verificacao = self.nav.texto(
                            "Descreva a verificação da correção")
                    inv.atualizar_vulnerabilidade(
                        ativo.id, vul.cve,
                        status=novo_status, verificacao=nova_verificacao,
                    )
                elif escolha == 4:
                    inv.atualizar_vulnerabilidade(
                        ativo.id, vul.cve,
                        verificacao=self.nav.texto(
                            "Verificação", padrao=atual.verificacao),
                    )
        self.transacao(preparar)

    def remover_vulnerabilidade(self):
        ativo, vul = self.escolher_vulnerabilidade()
        if not self.nav.confirmar(
            f"Remover {vul.cve} de {ativo.nome}?", risco=True
        ):
            raise OperacaoCancelada()
        self.transacao(
            lambda inv: inv.excluir_vulnerabilidade(ativo.id, vul.cve, True),
            confirmar=False,
        )

    def listar_dependencias(self):
        tabela = Table(box=box.ROUNDED)
        for titulo in ("Ativo dependente", "Depende de", "Peso"):
            tabela.add_column(titulo)
        for ativo in self.inventario.values():
            for dep in ativo.dependencias:
                origem = self.inventario.consultar_por_id(dep["ativo_id"])
                tabela.add_row(
                    f"#{ativo.id} {ativo.nome}",
                    f"#{origem.id} {origem.nome}" if origem else "Referência inválida",
                    f"{dep['peso']:.2f}",
                )
        self.console.print(tabela)
        self.console.print(
            "[dim]O ativo da primeira coluna herda uma fração do risco "
            "efetivo do ativo da segunda coluna.[/]"
        )

    def nova_dependencia(self):
        destino = self.escolher_ativo(
            mensagem="Qual ativo RECEBE o risco herdado?"
        )
        origem = self.escolher_ativo(
            mensagem="De qual ativo ele DEPENDE?"
        )
        peso = self.nav.texto(
            "Fração de risco transmitida (ex.: 0,25)"
        )
        self.transacao(
            lambda inv: inv.adicionar_dependencia(destino.id, origem.id, peso)
        )

    def remover_dependencia(self):
        pares = [
            (ativo, dep) for ativo in self.inventario.values()
            for dep in ativo.dependencias
        ]
        if not pares:
            raise DadosInvalidosError("Não há dependências cadastradas.")
        indice = self.nav.escolha(
            "Selecione a dependência a remover",
            [f"#{a.id} {a.nome} recebe do #{d['ativo_id']} ({d['peso']:.2f})"
             for a, d in pares],
        )
        ativo, dep = pares[indice]
        if not self.nav.confirmar("Excluir essa dependência?", risco=True):
            raise OperacaoCancelada()
        self.transacao(
            lambda inv: inv.remover_dependencia(ativo.id, dep["ativo_id"]),
            confirmar=False,
        )

    def analise(self):
        lista, m, v, b, a, x = AnalisadorRisco(self.inventario.ativos).calcular()
        _, cves, _ = montar_matriz_incidencia(self.inventario.ativos)
        tabela = Table(title="Risco por equipamento", box=box.ROUNDED, expand=True)
        for campo in ("ID", "Equipamento", "Próprio (b)", "Herdado", "Efetivo (x)"):
            tabela.add_column(campo)
        for i, ativo in enumerate(lista):
            tabela.add_row(
                str(ativo.id), ativo.nome, f"{b[i]:.2f}",
                f"{x[i] - b[i]:+.2f}", f"{x[i]:.2f}",
            )
        self.console.print(tabela)
        self.console.print(Panel(
            "b = Mv    |    x = b + Ax    |    (I-A)x = b\n"
            "M: incidência de CVE por ativo. v: notas CVSS. A: dependências.\n"
            "[yellow]O risco calculado é um índice acadêmico, não uma nota CVSS.[/]",
            title="Modelo matemático da avaliação",
            border_style=COR,
        ))
        escolha = self.nav.escolha(
            "Detalhamento do modelo",
            ["Exibir matrizes M e A + vetor v", "Simular nova vulnerabilidade",
             "Voltar"],
        )
        if escolha == 0:
            if not lista:
                self.aviso("Ainda não há ativos cadastrados.")
                return
            incidencia = Table(
                title=f"M — {len(lista)} × {len(cves)}",
                box=box.SIMPLE,
            )
            incidencia.add_column("Ativo")
            for vul in cves:
                incidencia.add_column(vul.cve)
            for ativo, linha in zip(lista, m):
                incidencia.add_row(
                    f"#{ativo.id}", *(str(valor) for valor in linha)
                )
            self.console.print(incidencia)
            self.console.print(f"[bold]v (CVSS):[/] {v}")
            deps = Table(
                title=f"A — {len(lista)} × {len(lista)}", box=box.SIMPLE
            )
            deps.add_column("Ativo")
            for ativo in lista:
                deps.add_column(str(ativo.id))
            for ativo, linha in zip(lista, a):
                deps.add_row(
                    str(ativo.id), *(f"{peso:.2f}" for peso in linha)
                )
            self.console.print(deps)
            analisador = AnalisadorRisco(self.inventario.ativos)
            analisador.calcular()
            self.console.print(
                "[green]I-A invertível[/]  |  "
                f"condicionamento ∞: {analisador.numero_condicao:.3e}"
            )
        elif escolha == 1:
            self.simulacao()

    def simulacao(self):
        ativo = self.escolher_ativo()
        cvss = self.nav.texto(
            "Severidade CVSS hipotética", conversor=validar_cvss
        )
        lista, _, _, proprio_antigo, _, efetivo_antigo = (
            AnalisadorRisco(self.inventario.ativos).calcular()
        )
        _, _, _, proprio_novo, _, efetivo_novo = simular_vulnerabilidade(
            self.inventario.ativos, ativo.id, cvss,
        )
        tabela = Table(
            title="Cenário hipotético — NENHUM dado será salvo", box=box.ROUNDED
        )
        for col in ("Ativo", "Próprio atual", "Próprio simulado",
                    "Efetivo atual", "Efetivo simulado"):
            tabela.add_column(col)
        for i, item in enumerate(lista):
            tabela.add_row(
                item.nome, f"{proprio_antigo[i]:.2f}",
                f"{proprio_novo[i]:.2f}", f"{efetivo_antigo[i]:.2f}",
                f"{efetivo_novo[i]:.2f}",
            )
        self.console.print(tabela)

    def diagnostico(self):
        self.console.print("[cyan]Executando testes isolados...[/]")
        pasta = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        testes = unittest.defaultTestLoader.discover(pasta, pattern="test*.py")
        resultado = unittest.TextTestRunner(verbosity=1).run(testes)
        cor = "green" if resultado.wasSuccessful() else "red"
        self.aviso(
            f"Testes: {resultado.testsRun}  |  "
            f"Falhas: {len(resultado.failures)}  |  "
            f"Erros: {len(resultado.errors)}  |  "
            f"Ignorados: {len(resultado.skipped)}",
            cor,
        )
        self.console.print(
            "[dim]24 horas no Docker exigem uma evidência separada no servidor.[/]"
        )

    def menu_ativos(self):
        self.executar_tela("Equipamentos", [
            ("Listar equipamentos", self.listar_ativos),
            ("Consultar ficha completa", self.mostrar_ficha),
            ("Cadastrar equipamento", self.novo_ativo),
            ("Atualizar equipamento", self.atualizar_ativo),
            ("Excluir equipamento", self.remover_ativo),
            ("Gerenciar campos adicionais", self.campos_adicionais),
            ("Consultar categorias disponíveis", self.ver_categorias),
        ])

    def menu_vulnerabilidades(self):
        self.executar_tela("Vulnerabilidades", [
            ("Listar vulnerabilidades", self.listar_vulnerabilidades),
            ("Consultar ficha", self.ficha_vulnerabilidade),
            ("Cadastrar vulnerabilidade", self.nova_vulnerabilidade),
            ("Atualizar vulnerabilidade", self.atualizar_vulnerabilidade),
            ("Excluir vulnerabilidade", self.remover_vulnerabilidade),
        ])

    def menu_dependencias(self):
        self.executar_tela("Dependências", [
            ("Listar dependências", self.listar_dependencias),
            ("Adicionar dependência", self.nova_dependencia),
            ("Remover dependência", self.remover_dependencia),
        ])

    def executar(self):
        self.executar_tela("Menu principal", [
            ("Equipamentos", self.menu_ativos),
            ("Vulnerabilidades", self.menu_vulnerabilidades),
            ("Dependências", self.menu_dependencias),
            ("Análise matemática e simulações", self.analise),
            ("Diagnóstico e testes", self.diagnostico),
        ])
        self.console.print("[green]Programa encerrado com segurança.[/]")
