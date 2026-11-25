"""Telas de vulnerabilidades dos equipamentos."""

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apresentacao.navegacao import OperacaoCancelada
from dominio.modelos import SEVERIDADES, STATUS
from dominio.validacoes import validar_cve, validar_cvss, validar_cwe, validar_data_fonte


class TelasVulnerabilidades:
    """Telas de vulnerabilidades dos equipamentos."""

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
            id_ativo,
            cve,
            cwe,
            cvss,
            descricao,
            fonte,
            data,
            impacto,
            prioridade,
            tratamento,
            status,
            verificacao,
        )

    def listar_vulnerabilidades(self):
        registros = self.inventario.consultar_vulnerabilidades()
        if not registros:
            self.aviso("Nenhuma vulnerabilidade cadastrada.")
            return
        if self.console.width < 74:
            colunas = ("ID", "CVE", "CVSS", "Status")
            linhas = [
                (ativo.id, vul.cve, f"{vul.cvss:.1f}", vul.status) for ativo, vul in registros
            ]
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
            "Buscar vulnerabilidade",
            ["Por CVE", "Por equipamento", "Por situação", "Por prioridade"],
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
        ativo, vul = (
            registros[0] if len(registros) == 1 else self.escolher_vulnerabilidade(registros)
        )
        self.mostrar_vulnerabilidade(ativo, vul)

    def mostrar_vulnerabilidade(self, ativo, vul):
        tabela = Table(box=box.SIMPLE, show_header=False)
        tabela.add_column("Campo", style="bold cyan")
        tabela.add_column("Valor")
        campos = [
            ("Ativo", f"#{ativo.id} {ativo.nome}"),
            ("CVE", vul.cve),
            ("CWE", vul.cwe),
            ("CVSS", f"{vul.cvss:.1f}"),
            ("Descrição", vul.descricao),
            ("Fonte", vul.fonte),
            ("Data", vul.data_fonte),
            ("Impacto", vul.impacto),
            ("Prioridade", vul.prioridade),
            ("Tratamento", vul.tratamento),
            ("Status", vul.status),
            ("Verificação", vul.verificacao),
        ]
        for campo, valor in campos:
            tabela.add_row(campo, Text(str(valor)))
        self.console.print(Panel(tabela, title="Ficha da vulnerabilidade"))

    def nova_vulnerabilidade(self):
        ativo = self.escolher_ativo()
        self.transacao(lambda inv: self.coletar_vulnerabilidade(inv, ativo.id))

    def atualizar_vulnerabilidade(self):
        ativo, vul = self.escolher_vulnerabilidade()

        def preparar(inv):
            while True:
                atual = inv.consultar_por_id(ativo.id).buscar_vulnerabilidade(vul.cve)
                opcoes = [
                    "Descrição",
                    "Prioridade",
                    "Tratamento",
                    "Status",
                    "Verificação",
                    "Salvar alterações",
                ]
                escolha = self.nav.escolha("Editar vulnerabilidade", opcoes)
                if escolha == 5:
                    return
                if escolha == 0:
                    inv.atualizar_vulnerabilidade(
                        ativo.id,
                        vul.cve,
                        descricao=self.nav.texto("Descrição", padrao=atual.descricao),
                    )
                elif escolha == 1:
                    inv.atualizar_vulnerabilidade(
                        ativo.id,
                        vul.cve,
                        prioridade=self.escolher_opcao("Prioridade", SEVERIDADES, atual.prioridade),
                    )
                elif escolha == 2:
                    inv.atualizar_vulnerabilidade(
                        ativo.id,
                        vul.cve,
                        tratamento=self.nav.texto("Tratamento", padrao=atual.tratamento),
                    )
                elif escolha == 3:
                    novo_status = self.escolher_opcao("Status", STATUS, atual.status)
                    nova_verificacao = None
                    if novo_status == "Corrigida" and atual.verificacao.lower() == "pendente":
                        nova_verificacao = self.nav.texto("Descreva a verificação da correção")
                    inv.atualizar_vulnerabilidade(
                        ativo.id,
                        vul.cve,
                        status=novo_status,
                        verificacao=nova_verificacao,
                    )
                elif escolha == 4:
                    inv.atualizar_vulnerabilidade(
                        ativo.id,
                        vul.cve,
                        verificacao=self.nav.texto("Verificação", padrao=atual.verificacao),
                    )

        self.transacao(preparar)

    def remover_vulnerabilidade(self):
        ativo, vul = self.escolher_vulnerabilidade()
        if not self.nav.confirmar(f"Remover {vul.cve} de {ativo.nome}?", risco=True):
            raise OperacaoCancelada()
        self.transacao(
            lambda inv: inv.excluir_vulnerabilidade(ativo.id, vul.cve, True),
            confirmar=False,
        )
