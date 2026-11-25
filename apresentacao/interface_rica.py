"""Interface de terminal com navegação por setas e alterações em rascunho."""
import os
import subprocess
import sys
from copy import deepcopy

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
from dominio.risco import AnalisadorRisco, simular_vulnerabilidade
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
        self.resumo_risco = None

    def cabecalho(self, titulo="Painel geral"):
        c = self.console
        if c.is_terminal:
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
        c.print(
            f"[bold]{len(ativos)}[/] ativos   |   "
            f"[bold]{qtd_cve}[/] registros de vulnerabilidade"
        )
        if titulo == "Menu principal":
            if self.resumo_risco is None:
                try:
                    _, _, _, proprio, _, efetivo = AnalisadorRisco(self.inventario.ativos).calcular()
                    self.resumo_risco = f"Risco próprio total: {sum(proprio):.2f}  |  Risco efetivo total: {sum(efetivo):.2f}"
                except (ValueError, KeyError, ZeroDivisionError) as erro:
                    self.resumo_risco = f"Cálculo indisponível: {erro}"
            c.print(Text(self.resumo_risco, style="dim"))
        c.rule(f"[bold {COR}]{titulo}[/]")

    def aviso(self, mensagem, estilo="yellow"):
        self.console.print(Panel(Text(str(mensagem)), border_style=estilo, expand=False))

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
                return False
            try:
                if acoes[indice][1]() is False:
                    continue
            except OperacaoCancelada:
                self.aviso("Operação cancelada. Nenhuma alteração foi salva.", "yellow")
            except (DadosInvalidosError, ValueError, KeyError, OSError) as erro:
                self.aviso(f"Não foi possível concluir: {erro}", "red")
            self.pausar()

    def transacao(self, modificar, confirmar=True, perigosa=False):
        """Só publica no objeto vivo após validar e gravar o rascunho."""
        rascunho = Inventario(deepcopy(self.inventario.ativos))
        modificar(rascunho)
        if confirmar and not self.nav.confirmar(
            "Salvar as alterações?", risco=perigosa
        ):
            raise OperacaoCancelada()
        # Reconstrói M, v e A antes de persistir o rascunho confirmado.
        _, _, _, proprio, _, efetivo = AnalisadorRisco(rascunho.ativos).calcular()
        if not RepositorioJSON(self.caminho_dados).salvar(rascunho.ativos):
            raise DadosInvalidosError("Falha na gravação: dados anteriores preservados.")
        self.inventario._ativos = rascunho.ativos
        self.resumo_risco = f"Risco próprio total: {sum(proprio):.2f}  |  Risco efetivo total: {sum(efetivo):.2f}"
        self.aviso(
            "Alteração salva. Matrizes e indicadores de risco recalculados.",
            "green",
        )

    def escolher_ativo(self, inventario=None, mensagem="Selecione o ativo", resultados=None):
        """Paginador para inventários maiores que uma tela."""
        inventario = self.inventario if inventario is None else inventario
        ativos = sorted(
            inventario.values() if resultados is None else resultados,
            key=lambda item: item.id,
        )
        if not ativos:
            raise DadosInvalidosError("Ainda não há ativos cadastrados.")
        return self.escolher_em_paginas(
            mensagem, ativos, lambda ativo: f"#{ativo.id} {ativo.nome} · {ativo.nome_do_tipo()}",
        )

    def escolher_vulnerabilidade(self, registros=None):
        if registros is None:
            registros = self.inventario.consultar_vulnerabilidades()
        if not registros:
            raise DadosInvalidosError("Nenhuma vulnerabilidade cadastrada.")
        return self.escolher_em_paginas(
            "Escolha a vulnerabilidade", registros,
            lambda item: f"{item[1].cve} · #{item[0].id} {item[0].nome} · CVSS {item[1].cvss:.1f}",
        )

    def escolher_em_paginas(self, titulo, registros, rotulo):
        tamanho = max(1, min(10, self.console.height - 12))
        ultima = (len(registros) - 1) // tamanho
        pagina = 0
        while True:
            trecho = registros[pagina * tamanho:(pagina + 1) * tamanho]
            passos = self.passos_pagina(pagina, ultima)
            opcoes = [rotulo(item) for item in trecho] + list(passos)
            escolha = self.nav.escolha(f"{titulo} · {pagina + 1}/{ultima + 1}", opcoes)
            if escolha < len(trecho):
                return trecho[escolha]
            pagina += passos[opcoes[escolha]]

    @staticmethod
    def passos_pagina(pagina, ultima):
        passos = {}
        if pagina:
            passos["← Página anterior"] = -1
        if pagina < ultima:
            passos["→ Próxima página"] = 1
        return passos

    def escolher_opcao(self, titulo, valores, atual=None):
        indice = valores.index(atual) if atual in valores else 0
        return valores[self.nav.escolha(titulo, valores, indice)]

    def escolher_tipo(self, inventario):
        tipos = inventario.listar_tipos()
        escolhas = list(tipos.items()) + [(None, "Criar categoria personalizada")]
        tipo, nome = self.escolher_em_paginas(
            "Categoria do ativo", escolhas,
            lambda item: f"{item[0]} · {item[1]}" if item[0] is not None else f"+ {item[1]}",
        )
        if tipo is not None:
            return tipo, nome if tipo >= 100 else None
        codigo = self.nav.inteiro("Novo código de categoria (a partir de 100)")
        if codigo < 100 or codigo in tipos:
            raise DadosInvalidosError(
                "Código personalizado deve ser novo e maior ou igual a 100."
            )
        nome = self.nav.texto("Nome da categoria")
        return codigo, nome

    def listar_ativos(self):
        ativos = sorted(self.inventario.values(), key=lambda ativo: ativo.id)
        if not ativos:
            self.aviso("Nenhum ativo cadastrado.")
            return
        return self.mostrar_ativos(ativos)

    def mostrar_ativos(self, ativos):
        if self.console.width < 74:
            colunas = ("ID", "Hostname", "CVEs")
            linhas = [(a.id, a.nome, len(a.vulnerabilidades)) for a in ativos]
        else:
            colunas = ("ID", "Hostname", "Tipo", "Responsável", "Criticidade", "CVEs")
            linhas = [
                (a.id, a.nome, a.nome_do_tipo(), a.responsavel, a.criticidade, len(a.vulnerabilidades))
                for a in ativos
            ]
        return self.mostrar_lista("Equipamentos", colunas, linhas)

    def mostrar_lista(self, titulo, colunas, linhas):
        tamanho = max(1, min(12, self.console.height - 12))
        pagina = 0
        ultima = (len(linhas) - 1) // tamanho
        while True:
            faixa = linhas[pagina * tamanho:(pagina + 1) * tamanho]
            self.imprimir_tabela(f"{titulo} · {pagina + 1}/{ultima + 1}", colunas, faixa)
            passos = self.passos_pagina(pagina, ultima)
            if not passos:
                return
            opcoes = list(passos) + ["Voltar"]
            escolha = self.nav.menu("Páginas", opcoes)
            if escolha is None or escolha == len(passos):
                return False
            pagina += passos[opcoes[escolha]]

    def imprimir_tabela(self, titulo, colunas, linhas):
        tabela = Table(title=titulo, box=box.ROUNDED, expand=True, header_style=COR)
        for coluna in colunas:
            tabela.add_column(coluna)
        for linha in linhas:
            tabela.add_row(*(Text(str(celula)) for celula in linha))
        self.console.print(tabela)

    def buscar_ativo(self):
        modo = self.nav.escolha("Buscar equipamento", ["Por ID", "Por nome ou hostname"])
        if modo == 0:
            ativo = self.inventario.consultar_por_id(self.nav.inteiro("ID do equipamento"))
            if ativo is None:
                raise DadosInvalidosError("Equipamento não encontrado.")
        else:
            nome = self.nav.texto("Nome ou parte do hostname")
            resultados = self.inventario.filtrar_ativos(termo=nome)
            if not resultados:
                raise DadosInvalidosError("Nenhum equipamento encontrado com esse nome.")
            ativo = self.escolher_ativo(resultados=resultados) if len(resultados) > 1 else resultados[0]
        self.mostrar_ficha(ativo)

    def mostrar_ficha(self, ativo=None):
        if ativo is None:
            ativo = self.escolher_ativo()
        self.console.print(Panel(
            Text(ativo.nome + "\n", style="bold") + Text(
                f"ID: {ativo.id}     Tipo: {ativo.nome_do_tipo()} ({ativo.tipo})\n"
                f"Responsável: {ativo.responsavel}\n"
                f"Localização: {ativo.localizacao}\n"
                f"Criticidade: {ativo.criticidade}"
            ),
            title="Identificação do equipamento",
            border_style=COR,
        ))
        if ativo.campos_extras:
            tabela = Table(title="Campos adicionais", box=box.SIMPLE)
            tabela.add_column("Campo")
            tabela.add_column("Conteúdo")
            for chave, valor in ativo.campos_extras.items():
                tabela.add_row(Text(chave), Text(valor))
            self.console.print(tabela)
        else:
            self.console.print("[dim]Sem campos adicionais.[/]")
        tabela = Table(title="Vulnerabilidades associadas", box=box.ROUNDED)
        for nome in ("CVE", "CWE", "CVSS", "Status", "Prioridade"):
            tabela.add_column(nome)
        for v in ativo.vulnerabilidades:
            tabela.add_row(v.cve, v.cwe, f"{v.cvss:.1f}", v.status, v.prioridade)
        if ativo.vulnerabilidades:
            self.console.print(tabela)
        else:
            self.console.print("[green]Nenhuma vulnerabilidade registrada.[/]")
        if ativo.dependencias:
            self.console.print("[bold]Dependências:[/]")
            for dep in ativo.dependencias:
                self.console.print(
                    f"  • #{dep['ativo_id']}  |  peso {dep['peso']:.2f}"
                )
        self.console.print("[bold]Histórico:[/]")
        for linha in ativo.historico[-8:]:
            self.console.print(Text(f"  {linha}", style="dim"))

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
            tabela.add_row(str(codigo), Text(nome))
        self.console.print(tabela)
        self.console.print(
            "[dim]Novas categorias podem ser criadas no cadastro de ativos. "
            "Cada categoria personalizada usa código inteiro >= 100.[/]"
        )

    def listar_vulnerabilidades(self):
        registros = self.inventario.consultar_vulnerabilidades()
        if not registros:
            self.aviso("Nenhuma vulnerabilidade cadastrada.")
            return
        if self.console.width < 74:
            colunas = ("ID", "CVE", "CVSS", "Status")
            linhas = [(ativo.id, vul.cve, f"{vul.cvss:.1f}", vul.status) for ativo, vul in registros]
        else:
            colunas = ("Ativo", "CVE", "CWE", "CVSS", "Prioridade", "Status")
            linhas = [
                (ativo.nome, vul.cve, vul.cwe, f"{vul.cvss:.1f}", vul.prioridade, vul.status)
                for ativo, vul in registros
            ]
        return self.mostrar_lista("Vulnerabilidades", colunas, linhas)

    def ficha_vulnerabilidade(self):
        ativo, vul = self.escolher_vulnerabilidade()
        self.mostrar_vulnerabilidade(ativo, vul)

    def buscar_vulnerabilidade(self):
        modo = self.nav.escolha(
            "Buscar vulnerabilidade", ["Por CVE", "Por equipamento", "Por situação", "Por prioridade"],
        )
        if modo == 0:
            cve = self.nav.texto("Código CVE", conversor=validar_cve)
            registros = self.inventario.consultar_vulnerabilidades(cve=cve)
        elif modo == 1:
            ativo = self.escolher_ativo()
            registros = [(ativo, vulnerabilidade) for vulnerabilidade in ativo.vulnerabilidades]
        elif modo == 2:
            status = self.escolher_opcao("Situação", STATUS)
            registros = self.inventario.consultar_vulnerabilidades(status=status)
        else:
            prioridade = self.escolher_opcao("Prioridade", SEVERIDADES)
            registros = self.inventario.consultar_vulnerabilidades(prioridade=prioridade)
        if not registros:
            self.aviso("Nenhuma vulnerabilidade corresponde à busca.")
            return
        ativo, vul = registros[0] if len(registros) == 1 else self.escolher_vulnerabilidade(registros)
        self.mostrar_vulnerabilidade(ativo, vul)

    def mostrar_vulnerabilidade(self, ativo, vul):
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
            tabela.add_row(campo, Text(str(valor)))
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
        linhas = []
        for ativo in self.inventario.values():
            for dep in ativo.dependencias:
                origem = self.inventario.consultar_por_id(dep["ativo_id"])
                linhas.append((
                    f"#{ativo.id} {ativo.nome}",
                    f"#{origem.id} {origem.nome}" if origem else "Referência inválida",
                    f"{dep['peso']:.2f}",
                ))
        if not linhas:
            self.aviso("Não há dependências cadastradas.")
            return
        self.mostrar_lista("Dependências", ("Ativo dependente", "Depende de", "Peso"), linhas)
        self.console.print(
            "[dim]O ativo da primeira coluna herda uma fração do risco "
            "efetivo do ativo da segunda coluna.[/]"
        )

    def nova_dependencia(self):
        if len(self.inventario) < 2:
            self.aviso("Cadastre pelo menos dois equipamentos para criar uma dependência.")
            return
        destino = self.escolher_ativo(
            mensagem="Qual ativo RECEBE o risco herdado?"
        )
        ja_vinculados = {item["ativo_id"] for item in destino.dependencias}
        candidatos = [
            ativo for ativo in self.inventario.values()
            if ativo.id != destino.id and ativo.id not in ja_vinculados
        ]
        if not candidatos:
            self.aviso("Todos os outros equipamentos já são dependências deste ativo.")
            return
        origem = self.escolher_ativo(
            mensagem="De qual ativo ele DEPENDE?", resultados=candidatos,
        )
        peso = self.nav.texto(
            "Fração de risco transmitida (ex.: 0,25)"
        )
        self.transacao(
            lambda inv: inv.adicionar_dependencia(destino.id, origem.id, peso)
        )

    def escolher_dependencia(self, titulo):
        pares = [
            (ativo, dep) for ativo in self.inventario.values()
            for dep in ativo.dependencias
        ]
        if not pares:
            raise DadosInvalidosError("Não há dependências cadastradas.")
        return self.escolher_em_paginas(
            titulo, pares,
            lambda item: f"#{item[0].id} {item[0].nome} recebe do #{item[1]['ativo_id']} ({item[1]['peso']:.2f})",
        )

    def editar_dependencia(self):
        ativo, dep = self.escolher_dependencia("Selecione a dependência a atualizar")
        origem = dep["ativo_id"]
        peso = self.nav.texto("Novo peso (fração entre 0 e 1)", padrao=dep["peso"])

        def preparar(inv):
            inv.remover_dependencia(ativo.id, origem)
            inv.adicionar_dependencia(ativo.id, origem, peso)

        self.transacao(preparar)

    def remover_dependencia(self):
        ativo, dep = self.escolher_dependencia("Selecione a dependência a remover")
        if not self.nav.confirmar("Excluir essa dependência?", risco=True):
            raise OperacaoCancelada()
        self.transacao(
            lambda inv: inv.remover_dependencia(ativo.id, dep["ativo_id"]),
            confirmar=False,
        )

    def analise(self):
        if not self.inventario:
            self.aviso("Ainda não há ativos cadastrados.")
            return
        analisador = AnalisadorRisco(self.inventario.ativos)
        lista, m, v, b, a, x = analisador.calcular()
        linhas = []
        for i in sorted(range(len(lista)), key=lambda pos: (-x[pos], lista[pos].id)):
            ativo = lista[i]
            linhas.append((
                f"#{ativo.id} {ativo.nome}", f"{b[i]:.2f}", f"{analisador.herdado[i]:+.2f}", f"{x[i]:.2f}",
            ))
        if self.mostrar_lista("Equipamentos por risco efetivo", ("Equipamento", "Próprio", "Herdado", "Efetivo"), linhas) is False:
            return False
        self.console.print(Panel(
            "b = F·Mv    |    x = b + Ax    |    (I-A)x = b\n"
            "M: incidência de CVE por ativo. v: notas CVSS. A: dependências. F: fator de exposição do tipo.\n"
            "[yellow]O risco calculado é um índice acadêmico, não uma nota CVSS.[/]",
            title="Modelo matemático da avaliação",
            border_style=COR,
        ))
        escolha = self.nav.escolha(
            "Detalhamento do modelo",
            ["Matrizes, vetores e verificação", "Explicar a conta de um equipamento",
             "Simular nova vulnerabilidade", "Voltar"],
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
                    ("v", v), ("F", analisador.fatores), ("b", b),
                    ("Ax", analisador.herdado), ("x", x),
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
                for j, (origem, peso) in enumerate(zip(lista, a[i])) if peso
            )
            conta = (
                f"Mv = {proprios or '0'} = {analisador.soma_cvss[i]:.6g}\n"
                f"b = F·Mv = {analisador.fatores[i]:.6g} × {analisador.soma_cvss[i]:.6g} = {b[i]:.6g}\n"
                f"Ax = {herdados or '0'} = {analisador.herdado[i]:.6g}\n"
                f"x = b + Ax = {b[i]:.6g} + {analisador.herdado[i]:.6g} = {x[i]:.6g}"
            )
            self.console.print(Panel(
                conta, title=Text(f"Conta de #{ativo.id} · {ativo.nome}"),
            ))
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
        cvss = self.nav.texto(
            "Severidade CVSS hipotética", conversor=validar_cvss
        )
        lista, _, _, proprio_antigo, _, efetivo_antigo = (
            AnalisadorRisco(self.inventario.ativos).calcular()
        )
        _, _, _, proprio_novo, _, efetivo_novo = simular_vulnerabilidade(
            self.inventario.ativos, ativo.id, cvss,
        )
        linhas = [
            (item.nome, f"{proprio_antigo[i]:.2f} → {proprio_novo[i]:.2f}",
             f"{efetivo_antigo[i]:.2f} → {efetivo_novo[i]:.2f}",
             f"{efetivo_novo[i] - efetivo_antigo[i]:+.2f}")
            for i, item in enumerate(lista)
        ]
        return self.mostrar_lista(
            "Simulação temporária", ("Ativo", "Próprio", "Efetivo", "Variação"), linhas,
        )

    def diagnostico(self):
        pasta = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        resultado = subprocess.run(
            [sys.executable, "app.py", "--testes"], cwd=pasta, check=False,
        )
        if resultado.returncode:
            self.aviso("O Pytest não concluiu com sucesso. Veja a saída acima.", "red")

    def menu_ativos(self):
        return self.executar_tela("Equipamentos", [
            ("Listar equipamentos", self.listar_ativos),
            ("Buscar por ID ou hostname", self.buscar_ativo),
            ("Consultar ficha completa", self.mostrar_ficha),
            ("Cadastrar equipamento", self.novo_ativo),
            ("Atualizar equipamento", self.atualizar_ativo),
            ("Excluir equipamento", self.remover_ativo),
            ("Gerenciar campos adicionais", self.campos_adicionais),
            ("Consultar categorias disponíveis", self.ver_categorias),
        ])

    def menu_vulnerabilidades(self):
        return self.executar_tela("Vulnerabilidades", [
            ("Listar vulnerabilidades", self.listar_vulnerabilidades),
            ("Buscar por CVE, equipamento, situação ou prioridade", self.buscar_vulnerabilidade),
            ("Consultar ficha", self.ficha_vulnerabilidade),
            ("Cadastrar vulnerabilidade", self.nova_vulnerabilidade),
            ("Atualizar vulnerabilidade", self.atualizar_vulnerabilidade),
            ("Excluir vulnerabilidade", self.remover_vulnerabilidade),
        ])

    def menu_dependencias(self):
        return self.executar_tela("Dependências", [
            ("Listar dependências", self.listar_dependencias),
            ("Adicionar dependência", self.nova_dependencia),
            ("Alterar peso de uma dependência", self.editar_dependencia),
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
