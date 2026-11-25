"""Telas das dependências entre equipamentos."""

from apresentacao.navegacao import OperacaoCancelada
from dominio.validacoes import DadosInvalidosError


class TelasDependencias:
    """Telas das dependências entre equipamentos."""

    def listar_dependencias(self):
        linhas = []
        for ativo in self.inventario.values():
            for dep in ativo.dependencias:
                origem = self.inventario.consultar_por_id(dep["ativo_id"])
                linhas.append(
                    (
                        f"#{ativo.id} {ativo.nome}",
                        f"#{origem.id} {origem.nome}" if origem else "Referência inválida",
                        f"{dep['peso']:.2f}",
                    )
                )
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
        destino = self.escolher_ativo(mensagem="Qual ativo RECEBE o risco herdado?")
        ja_vinculados = {item["ativo_id"] for item in destino.dependencias}
        candidatos = [
            ativo
            for ativo in self.inventario.values()
            if ativo.id != destino.id and ativo.id not in ja_vinculados
        ]
        if not candidatos:
            self.aviso("Todos os outros equipamentos já são dependências deste ativo.")
            return
        origem = self.escolher_ativo(
            mensagem="De qual ativo ele DEPENDE?",
            resultados=candidatos,
        )
        peso = self.nav.texto("Fração de risco transmitida (ex.: 0,25)")
        self.transacao(lambda inv: inv.adicionar_dependencia(destino.id, origem.id, peso))

    def escolher_dependencia(self, titulo):
        pares = [(ativo, dep) for ativo in self.inventario.values() for dep in ativo.dependencias]
        if not pares:
            raise DadosInvalidosError("Não há dependências cadastradas.")
        return self.escolher_em_paginas(
            titulo,
            pares,
            lambda item: (
                f"#{item[0].id} {item[0].nome} recebe do #{item[1]['ativo_id']} "
                f"({item[1]['peso']:.2f})"
            ),
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
