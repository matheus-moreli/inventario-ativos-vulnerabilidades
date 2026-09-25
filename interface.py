"""Entradas e saídas do terminal. As regras estão em inventario.py."""

import ctypes
import msvcrt
import os
import sys

from inventario import (DadosInvalidosError, atualizar_ativo, atualizar_vulnerabilidade,
                        buscar_vulnerabilidade, cadastrar_ativo,
                        cadastrar_vulnerabilidade, consultar_por_id,
                        consultar_vulnerabilidades, excluir_ativo,
                        excluir_vulnerabilidade, filtrar_ativos, validar_cve,
                        validar_cwe, validar_cvss, validar_data_fonte)
from modelos import CRITICIDADES, SEVERIDADES, STATUS, TipoAtivo
from persistencia import salvar_ativos

# Valor especial usado apenas pela interface para voltar uma etapa do formulário.
VOLTAR = object()


def ativar_cores():
    """Ativa cores ANSI no Windows somente quando o terminal as suporta."""
    # O programa continua legível sem cores, inclusive quando a saída é redirecionada.
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    try:
        console = ctypes.windll.kernel32
        saida = console.GetStdHandle(-11)
        modo = ctypes.c_uint()
        if saida == -1 or not console.GetConsoleMode(saida, ctypes.byref(modo)):
            return False
        return bool(console.SetConsoleMode(saida, modo.value | 0x0004))
    except (AttributeError, OSError):
        return False


USAR_CORES = ativar_cores()


def colorir(texto, codigo):
    """Aplica uma cor ANSI, mas devolve texto normal se ela não estiver disponível."""
    if not USAR_CORES:
        return texto
    return f"\033[{codigo}m{texto}\033[0m"


def mostrar_sucesso(mensagem):
    print(colorir(f"[OK] {mensagem}", "92"))


def mostrar_erro(mensagem):
    print(colorir(f"[ERRO] {mensagem}", "91"))


def mostrar_aviso(mensagem):
    print(colorir(f"[!] {mensagem}", "93"))


def mostrar_linha():
    # Uma função curta mantém o mesmo separador em todas as telas.
    print(colorir("-" * 65, "36"))


def mostrar_titulo(titulo):
    """Padroniza os títulos das telas sem depender de caracteres especiais."""
    mostrar_linha()
    print(colorir(titulo.upper(), "1;96"))
    mostrar_linha()


def ler_texto(mensagem, obrigatorio=True):
    # A validação na tela evita enviar campos vazios à regra de negócio.
    while True:
        texto = input(mensagem).strip()
        if texto or not obrigatorio:
            return texto
        mostrar_aviso("Este campo não pode ficar vazio.")


def ler_inteiro(mensagem):
    # try impede que uma conversão inválida encerre o programa.
    while True:
        try:
            numero = int(input(mensagem).strip())
            if numero > 0:
                return numero
            mostrar_aviso("Digite um número maior que zero.")
        except ValueError:
            mostrar_erro("Digite somente um número inteiro válido.")


def ler_sim_ou_nao(mensagem):
    indice = escolher_com_setas(mensagem, ["Sim", "Não"])
    return indice == 0


def ler_cve(mensagem):
    """Valida o CVE logo após a digitação, sem perder as outras respostas."""
    while True:
        try:
            return validar_cve(ler_texto(mensagem))
        except DadosInvalidosError as erro:
            mostrar_erro(str(erro))


def ler_cwe(mensagem):
    """Valida o CWE logo após a digitação."""
    while True:
        try:
            return validar_cwe(ler_texto(mensagem))
        except DadosInvalidosError as erro:
            mostrar_erro(str(erro))


def ler_cvss(mensagem):
    """Lê uma nota CVSS válida no intervalo de 0.0 a 10.0."""
    while True:
        try:
            return validar_cvss(ler_texto(mensagem))
        except DadosInvalidosError as erro:
            mostrar_erro(str(erro))


def ler_data_fonte(mensagem):
    """Mantém a data da fonte no formato dd/mm/aaaa anunciado pelo menu."""
    while True:
        try:
            return validar_data_fonte(ler_texto(mensagem))
        except DadosInvalidosError as erro:
            mostrar_erro(str(erro))


def ler_texto_formulario(mensagem, obrigatorio=True, valor_anterior=None, preenchido=False):
    """Lê texto com seta para esquerda/direita sem perder o valor atual."""
    # Nesta leitura, as setas não movem o cursor do texto: elas navegam pelo formulário.
    texto = list(str(valor_anterior) if preenchido and valor_anterior is not None else "")
    print(f"{mensagem}: {''.join(texto)}", end="", flush=True)
    while True:
        tecla = msvcrt.getwch()
        # No Windows, \xe0 também representa a letra "à". Uma seta sempre vem
        # acompanhada do segundo código; a letra chega sozinha.
        if tecla == "\x00" or (tecla == "\xe0" and msvcrt.kbhit()):
            codigo = msvcrt.getwch()
            if codigo == "K":  # seta para a esquerda
                print()
                return VOLTAR
            if codigo == "M":  # seta para a direita
                resposta = "".join(texto).strip()
                if resposta or not obrigatorio:
                    print()
                    return resposta
                print()
                mostrar_aviso("Preencha este campo antes de avançar.")
                print(f"{mensagem}: ", end="", flush=True)
            elif tecla == "\xe0":
                # No texto colado, o próximo caractere já pode estar no buffer.
                # Se não for uma seta, \xe0 é a letra "à" e deve ser preservada.
                texto.append(tecla)
                print(tecla, end="", flush=True)
                if codigo >= " ":
                    texto.append(codigo)
                    print(codigo, end="", flush=True)
        elif tecla == "\r":
            resposta = "".join(texto).strip()
            if resposta or not obrigatorio:
                print()
                return resposta
            print()
            mostrar_aviso("Este campo não pode ficar vazio.")
            print(f"{mensagem}: ", end="", flush=True)
        elif tecla == "\b":
            if texto:
                texto.pop()
                print("\b \b", end="", flush=True)
        elif tecla >= " ":
            texto.append(tecla)
            print(tecla, end="", flush=True)


def ler_inteiro_formulario(mensagem, valor_anterior=None, preenchido=False):
    """Lê um ID positivo ou devolve VOLTAR quando a pessoa cancela."""
    while True:
        texto = ler_texto_formulario(mensagem, True, valor_anterior, preenchido)
        if texto is VOLTAR:
            return VOLTAR
        try:
            numero = int(texto)
            if numero > 0:
                return numero
            mostrar_aviso("Digite um número maior que zero.")
        except ValueError:
            mostrar_erro("Digite somente um número inteiro válido.")


def ler_id_para_operacao(mensagem):
    """Lê um ID em uma tela simples e permite cancelar com a seta esquerda."""
    identificador = ler_inteiro_formulario(mensagem)
    if identificador is VOLTAR:
        mostrar_aviso("Operação cancelada.")
        return None
    return identificador


def ler_validado_formulario(mensagem, validador, valor_anterior=None, preenchido=False):
    """Aplica uma validação sem perder a possibilidade de voltar."""
    while True:
        valor = ler_texto_formulario(mensagem, True, valor_anterior, preenchido)
        if valor is VOLTAR:
            return VOLTAR
        try:
            return validador(valor)
        except DadosInvalidosError as erro:
            mostrar_erro(str(erro))


def ler_verificacao_formulario(valores, mensagem, valor_anterior=None, preenchido=False,
                               obrigatorio=True, verificacao_atual=None):
    """Exige evidência antes de marcar uma vulnerabilidade como corrigida."""
    while True:
        verificacao = ler_texto_formulario(
            mensagem, obrigatorio, valor_anterior, preenchido
        )
        if verificacao is VOLTAR:
            return VOLTAR
        verificacao_final = verificacao or verificacao_atual or ""
        if (valores.get("status") == "Corrigida" and
                verificacao_final.lower() in ("", "pendente")):
            mostrar_erro("Informe como a correção foi verificada antes de concluir.")
            continue
        return verificacao


def confirmar_remocao():
    """Pede confirmação por setas, sem exigir que a pessoa digite uma palavra."""
    escolha = escolher_com_setas(
        "Confirma a remoção?", ["Confirmar", "Cancelar"], True, 1
    )
    return escolha == 0


def escolher_com_setas(titulo, opcoes, permitir_cancelar=False, indice_inicial=0,
                        permitir_avancar=False):
    """Devolve o índice escolhido com as setas do teclado e Enter."""
    # msvcrt faz parte do Python no Windows e lê uma tecla sem exigir input().
    # A seleção aparece em uma linha própria para funcionar também no cmd comum.
    print("\n" + colorir(titulo.rstrip(": "), "1;96"))
    for opcao in opcoes:
        print(f"  {opcao}")
    instrucao = "Use as setas para cima e para baixo e Enter para confirmar."
    if permitir_cancelar:
        instrucao += " A seta para a esquerda retorna ao campo anterior."
    if permitir_avancar:
        instrucao += " A seta para a direita avança mantendo a escolha atual."
    print(colorir(instrucao, "2"))

    selecionado = indice_inicial
    maior_opcao = max(len(opcao) for opcao in opcoes)
    while True:
        atual = f"> {opcoes[selecionado]:<{maior_opcao}}"
        print(f"\r{colorir(atual, '1;96')}", end="", flush=True)
        tecla = msvcrt.getch()

        # As setas chegam em duas partes: um prefixo e o código da direção.
        if tecla in (b"\x00", b"\xe0"):
            tecla = msvcrt.getch()
            if tecla == b"H":  # seta para cima
                selecionado = (selecionado - 1) % len(opcoes)
            elif tecla == b"P":  # seta para baixo
                selecionado = (selecionado + 1) % len(opcoes)
            elif tecla == b"K" and permitir_cancelar:  # seta para a esquerda
                print()
                return None
            elif tecla == b"M" and permitir_avancar:  # seta para a direita
                print()
                return selecionado
        elif tecla == b"\r":  # Enter
            print()
            return selecionado


def escolher_item(titulo, opcoes, permitir_vazio=False):
    """Escolhe uma categoria padronizada sem digitar seu nome."""
    if permitir_vazio:
        escolhas = ["Sem filtro / manter em branco"] + opcoes
        indice = escolher_com_setas(titulo, escolhas, True)
        if indice is None or indice == 0:
            return None
        return opcoes[indice - 1]

    indice = escolher_com_setas(titulo, opcoes)
    if indice is None:
        return None
    return opcoes[indice]


def escolher_tipo_ativo(permitir_vazio=False):
    tipos = list(TipoAtivo)
    nomes = [tipo.name.replace("_", " ").title() for tipo in tipos]
    indice = escolher_com_setas("Tipo de ativo:", nomes, permitir_vazio)
    if indice is None:
        return None
    return tipos[indice].value


def escolher_item_formulario(titulo, opcoes, valor_anterior=None, preenchido=False):
    """Escolhe uma categoria, voltando/avançando com as setas quando possível."""
    indice_inicial = opcoes.index(valor_anterior) if preenchido else 0
    indice = escolher_com_setas(titulo, opcoes, True, indice_inicial, preenchido)
    if indice is None:
        return VOLTAR
    return opcoes[indice]


def escolher_tipo_formulario(valor_anterior=None, preenchido=False):
    """Escolhe o tipo de ativo, voltando/avançando com as setas quando possível."""
    tipos = list(TipoAtivo)
    nomes = [tipo.name.replace("_", " ").title() for tipo in tipos]
    indice_inicial = [tipo.value for tipo in tipos].index(valor_anterior) if preenchido else 0
    indice = escolher_com_setas("Tipo de ativo:", nomes, True, indice_inicial, preenchido)
    if indice is None:
        return VOLTAR
    return tipos[indice].value


def escolher_item_atualizacao(titulo, opcoes, valor_anterior=None, preenchido=False):
    """Permite manter o valor atual, escolher outro ou voltar uma etapa."""
    escolhas = ["Manter valor atual"] + opcoes
    indice_inicial = escolhas.index(valor_anterior) if preenchido and valor_anterior in escolhas else 0
    indice = escolher_com_setas(titulo, escolhas, True, indice_inicial, preenchido)
    if indice is None:
        return VOLTAR
    if indice == 0:
        return None
    return opcoes[indice - 1]


def escolher_tipo_atualizacao(valor_anterior=None, preenchido=False):
    """Variação do seletor de tipo usada na atualização de um ativo."""
    tipos = list(TipoAtivo)
    nomes = ["Manter valor atual"] + [
        tipo.name.replace("_", " ").title() for tipo in tipos
    ]
    indice_inicial = (tipos.index(TipoAtivo(valor_anterior)) + 1) if preenchido and valor_anterior is not None else 0
    indice = escolher_com_setas("Novo tipo de ativo:", nomes, True, indice_inicial, preenchido)
    if indice is None:
        return VOLTAR
    if indice == 0:
        return None
    return tipos[indice - 1].value


def preencher_formulario(campos):
    """Percorre campos em ordem; a seta esquerda retorna uma posição."""
    valores = {}
    etapa = 0
    while etapa < len(campos):
        nome, leitor = campos[etapa]
        valor = leitor(valores, valores.get(nome), nome in valores)
        if valor is VOLTAR:
            if etapa == 0:
                mostrar_aviso("Operação cancelada. Nenhum dado foi salvo.")
                return None
            etapa -= 1
            continue
        valores[nome] = valor
        etapa += 1
    return valores


def nome_do_tipo(codigo):
    try:
        return TipoAtivo(codigo).name.replace("_", " ").title()
    except ValueError:
        return "Tipo não identificado"


def mostrar_vulnerabilidades(ativo):
    print(colorir("VULNERABILIDADES", "1;96"))
    if not ativo.vulnerabilidades:
        print("  Este ativo não possui vulnerabilidades registradas.")
        return
    for numero, vulnerabilidade in enumerate(ativo.vulnerabilidades, 1):
        print(f"  {numero}. {vulnerabilidade.cve} - {vulnerabilidade.descricao}")
        print(f"     CWE: {vulnerabilidade.cwe} | CVSS: {vulnerabilidade.cvss:.1f}")
        print(f"     Prioridade: {vulnerabilidade.prioridade} | Status: {vulnerabilidade.status}")
        print(f"     Fonte: {vulnerabilidade.fonte} ({vulnerabilidade.data_fonte})")
        print(f"     Impacto: {vulnerabilidade.impacto}")
        print(f"     Tratamento: {vulnerabilidade.tratamento}")
        print(f"     Verificação: {vulnerabilidade.verificacao}")


def mostrar_ativo(ativo, mostrar_detalhes=True):
    mostrar_titulo(f"Ativo #{ativo.id}")
    print(f"ID: {ativo.id}")
    print(f"Nome ou hostname: {ativo.nome}")
    print(f"Responsável: {ativo.responsavel}")
    print(f"Setor ou localização: {ativo.localizacao}")
    print(f"Tipo: {nome_do_tipo(ativo.tipo)} ({ativo.tipo})")
    # Este dado é do ativo: mostra o impacto de ele ser comprometido ou parar.
    # A severidade da vulnerabilidade é exibida separadamente, quando houver uma.
    print(f"Importância do ativo para a segurança: {ativo.criticidade}")
    if mostrar_detalhes:
        mostrar_vulnerabilidades(ativo)
        print("Histórico:")
        for evento in ativo.historico or ["Nenhuma alteração registrada."]:
            print(f"  - {evento}")


def cadastrar_ativo_tela(ativos):
    print()
    mostrar_titulo("Cadastro de ativo")

    def ler_id_novo(valores, anterior, preenchido):
        while True:
            identificador = ler_inteiro_formulario("ID único do ativo", anterior, preenchido)
            if identificador is VOLTAR:
                return VOLTAR
            if consultar_por_id(ativos, identificador) is None:
                return identificador
            mostrar_erro("Já existe um ativo com esse ID.")

    dados = preencher_formulario([
        ("identificador", ler_id_novo),
        ("nome", lambda valores, anterior, preenchido: ler_texto_formulario(
            "Nome ou hostname", True, anterior, preenchido
        )),
        ("responsavel", lambda valores, anterior, preenchido: ler_texto_formulario(
            "Responsável", True, anterior, preenchido
        )),
        ("localizacao", lambda valores, anterior, preenchido: ler_texto_formulario(
            "Setor ou localização", True, anterior, preenchido
        )),
        ("tipo", lambda valores, anterior, preenchido: escolher_tipo_formulario(
            anterior, preenchido
        )),
        ("criticidade", lambda valores, anterior, preenchido: escolher_item_formulario(
            "Importância do ativo para a segurança (criticidade): ", CRITICIDADES, anterior, preenchido
        )),
    ])
    if dados is None:
        return False
    try:
        ativo = cadastrar_ativo(ativos, dados["identificador"], dados["nome"],
            dados["responsavel"], dados["localizacao"], dados["tipo"],
            dados["criticidade"])
        mostrar_sucesso(f"Ativo {ativo.id} cadastrado com sucesso.")
        return True
    except DadosInvalidosError as erro:
        mostrar_erro(str(erro))
        return False


def listar_ativos_tela(ativos):
    print()
    mostrar_titulo("Ativos cadastrados")
    if not ativos:
        mostrar_aviso("Não há ativos cadastrados.")
        return
    for identificador in sorted(ativos):
        mostrar_ativo(ativos[identificador], False)


def buscar_ativo_tela(ativos):
    print()
    mostrar_titulo("Buscar ativo")
    escolha = escolher_com_setas("Buscar ativo:", [
        "Buscar por ID",
        "Filtrar por nome, tipo ou importância do ativo",
        "Retornar ao menu",
    ], True)
    if escolha is None or escolha == 2:
        return
    if escolha == 0:
        identificador = ler_id_para_operacao("ID do ativo")
        if identificador is None:
            return
        ativo = consultar_por_id(ativos, identificador)
        if ativo is None:
            mostrar_aviso("Ativo não encontrado.")
        else:
            mostrar_ativo(ativo)
    elif escolha == 1:
        termo = ler_texto("Nome ou hostname (vazio = todos): ", False)
        tipo = escolher_tipo_ativo() if ler_sim_ou_nao("Deseja filtrar por tipo?") else None
        criticidade = escolher_item(
            "Importância do ativo para a segurança (criticidade): ", CRITICIDADES
        ) if ler_sim_ou_nao("Deseja filtrar por importância do ativo?") else None
        resultado = filtrar_ativos(ativos, termo, tipo, criticidade)
        if not resultado:
            mostrar_aviso("Nenhum ativo encontrado.")
        for ativo in resultado:
            mostrar_ativo(ativo, False)


def atualizar_ativo_tela(ativos):
    print()
    mostrar_titulo("Atualização de ativo")

    def ler_id_existente(valores, anterior, preenchido):
        while True:
            identificador = ler_inteiro_formulario(
                "ID do ativo que será atualizado", anterior, preenchido
            )
            if identificador is VOLTAR:
                return VOLTAR
            if consultar_por_id(ativos, identificador) is not None:
                if anterior is not None and identificador != anterior:
                    # Trocar o alvo invalida as respostas preenchidas para o ativo anterior.
                    valores.clear()
                return identificador
            mostrar_erro("Ativo não encontrado.")

    def ativo_do_formulario(valores):
        return consultar_por_id(ativos, valores["identificador"])

    dados = preencher_formulario([
        ("identificador", ler_id_existente),
        ("nome", lambda valores, anterior, preenchido: ler_texto_formulario(
            f"Nome ou hostname [{ativo_do_formulario(valores).nome}]", False, anterior, preenchido
        )),
        ("responsavel", lambda valores, anterior, preenchido: ler_texto_formulario(
            f"Responsável [{ativo_do_formulario(valores).responsavel}]", False, anterior, preenchido
        )),
        ("localizacao", lambda valores, anterior, preenchido: ler_texto_formulario(
            f"Setor ou localização [{ativo_do_formulario(valores).localizacao}]", False, anterior, preenchido
        )),
        ("tipo", lambda valores, anterior, preenchido: escolher_tipo_atualizacao(
            anterior, preenchido
        )),
        ("criticidade", lambda valores, anterior, preenchido: escolher_item_atualizacao(
            "Nova importância do ativo para a segurança:", CRITICIDADES, anterior, preenchido
        )),
    ])
    if dados is None:
        return False
    if not any([dados["nome"], dados["responsavel"], dados["localizacao"],
                dados["tipo"] is not None, dados["criticidade"] is not None]):
        mostrar_aviso("Nenhum campo foi alterado.")
        return False
    try:
        atualizar_ativo(ativos, dados["identificador"], dados["nome"],
                         dados["responsavel"], dados["localizacao"],
                         dados["tipo"], dados["criticidade"])
        mostrar_sucesso("Ativo atualizado com sucesso. A alteração está no histórico.")
        return True
    except DadosInvalidosError as erro:
        mostrar_erro(str(erro))
        return False


def remover_ativo_tela(ativos):
    print()
    mostrar_titulo("Remoção de ativo")
    identificador = ler_id_para_operacao("ID do ativo que será removido")
    if identificador is None:
        return False
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        mostrar_erro("Ativo não encontrado.")
        return False
    print(f"Confirme o alvo: ID {ativo.id} - {ativo.nome}.")
    print("Política: a exclusão remove o ativo e as vulnerabilidades associadas.")
    try:
        if excluir_ativo(ativos, identificador, confirmar_remocao()):
            mostrar_sucesso("Ativo removido com sucesso.")
            return True
        mostrar_aviso("Remoção cancelada.")
        return False
    except DadosInvalidosError as erro:
        mostrar_erro(str(erro))
        return False


def cadastrar_vulnerabilidade_tela(ativos):
    print()
    mostrar_titulo("Cadastro de vulnerabilidade")

    def ler_id_existente(valores, anterior, preenchido):
        while True:
            identificador = ler_inteiro_formulario("ID do ativo afetado", anterior, preenchido)
            if identificador is VOLTAR:
                return VOLTAR
            if consultar_por_id(ativos, identificador) is not None:
                return identificador
            mostrar_erro("Ativo não encontrado.")

    def ler_cve_novo(valores, anterior, preenchido):
        while True:
            cve = ler_validado_formulario(
                "CVE (ex.: CVE-2024-1234)", validar_cve, anterior, preenchido
            )
            if cve is VOLTAR:
                return VOLTAR
            ativo = consultar_por_id(ativos, valores["identificador"])
            if buscar_vulnerabilidade(ativo, cve) is None:
                return cve
            mostrar_erro("Esta vulnerabilidade já foi cadastrada para o ativo.")

    dados = preencher_formulario([
        ("identificador", ler_id_existente),
        ("cve", ler_cve_novo),
        ("cwe", lambda valores, anterior, preenchido: ler_validado_formulario(
            "CWE (ex.: CWE-79)", validar_cwe, anterior, preenchido
        )),
        ("cvss", lambda valores, anterior, preenchido: ler_validado_formulario(
            "Nota CVSS (0.0 a 10.0)", validar_cvss, anterior, preenchido
        )),
        ("descricao", lambda valores, anterior, preenchido: ler_texto_formulario(
            "Descrição", True, anterior, preenchido
        )),
        ("fonte", lambda valores, anterior, preenchido: ler_texto_formulario(
            "Fonte verificável (URL ou órgão)", True, anterior, preenchido
        )),
        ("data_fonte", lambda valores, anterior, preenchido: ler_validado_formulario(
            "Data da fonte (dd/mm/aaaa)", validar_data_fonte, anterior, preenchido
        )),
        ("impacto", lambda valores, anterior, preenchido: ler_texto_formulario(
            "Impacto no ativo", True, anterior, preenchido
        )),
        ("prioridade", lambda valores, anterior, preenchido: escolher_item_formulario(
            "Prioridade:", SEVERIDADES, anterior, preenchido
        )),
        ("tratamento", lambda valores, anterior, preenchido: ler_texto_formulario(
            "Tratamento planejado", True, anterior, preenchido
        )),
        ("status", lambda valores, anterior, preenchido: escolher_item_formulario(
            "Status:", STATUS, anterior, preenchido
        )),
        ("verificacao", lambda valores, anterior, preenchido: ler_verificacao_formulario(
            valores, "Como será verificado o tratamento", anterior, preenchido
        )),
    ])
    if dados is None:
        return False
    try:
        vulnerabilidade = cadastrar_vulnerabilidade(
            ativos, dados["identificador"], dados["cve"], dados["cwe"], dados["cvss"],
            dados["descricao"], dados["fonte"], dados["data_fonte"], dados["impacto"],
            dados["prioridade"], dados["tratamento"], dados["status"], dados["verificacao"]
        )
        mostrar_sucesso(f"Vulnerabilidade {vulnerabilidade.cve} cadastrada com sucesso.")
        return True
    except DadosInvalidosError as erro:
        mostrar_erro(str(erro))
        return False


def resumo_vulnerabilidade(ativo, vulnerabilidade):
    """Monta uma opção curta para a lista de consulta."""
    # A lista precisa caber bem no terminal e, ainda assim, identificar o registro.
    nome_ativo = ativo.nome[:18]
    if len(ativo.nome) > 18:
        nome_ativo += "..."
    return (f"{vulnerabilidade.cve} | CVSS {vulnerabilidade.cvss:.1f} | "
            f"{vulnerabilidade.prioridade} | {nome_ativo}")


def mostrar_detalhes_vulnerabilidade(ativo, vulnerabilidade):
    """Exibe todos os dados da vulnerabilidade escolhida na lista."""
    mostrar_titulo(f"Vulnerabilidade {vulnerabilidade.cve}")
    print(f"Ativo afetado: {ativo.id} - {ativo.nome}")
    print(f"Descrição: {vulnerabilidade.descricao}")
    print(f"CWE: {vulnerabilidade.cwe} | CVSS: {vulnerabilidade.cvss:.1f}")
    print(f"Prioridade: {vulnerabilidade.prioridade} | Status: {vulnerabilidade.status}")
    print(f"Fonte: {vulnerabilidade.fonte} ({vulnerabilidade.data_fonte})")
    print(f"Impacto: {vulnerabilidade.impacto}")
    print(f"Tratamento: {vulnerabilidade.tratamento}")
    print(f"Verificação: {vulnerabilidade.verificacao}")


def navegar_vulnerabilidades(resultado):
    """Permite abrir registros de uma lista de vulnerabilidades."""
    if not resultado:
        mostrar_aviso("Nenhuma vulnerabilidade encontrada.")
        return

    opcoes = [resumo_vulnerabilidade(ativo, vulnerabilidade)
              for ativo, vulnerabilidade in resultado]
    while True:
        indice = escolher_com_setas(
            f"{len(resultado)} vulnerabilidade(s) - Enter abre; seta esquerda volta",
            opcoes, True
        )
        if indice is None:
            return
        ativo, vulnerabilidade = resultado[indice]
        mostrar_detalhes_vulnerabilidade(ativo, vulnerabilidade)
        aguardar_retorno_lista()


def aguardar_retorno_lista():
    """Mantém os detalhes visíveis até Enter ou a seta esquerda voltar à lista."""
    print(colorir("Pressione Enter ou a seta esquerda para voltar à lista.", "2"))
    while True:
        tecla = msvcrt.getch()
        if tecla == b"\r":
            return
        if tecla in (b"\x00", b"\xe0") and msvcrt.getch() == b"K":
            return


def consultar_vulnerabilidades_tela(ativos):
    print()
    mostrar_titulo("Consulta de vulnerabilidades")
    modo = escolher_com_setas("Como deseja consultar?", [
        "Ver vulnerabilidades cadastradas",
        "Ver vulnerabilidades de um ativo por ID",
        "Filtrar vulnerabilidades (avançado)",
        "Retornar ao menu",
    ], True)
    if modo is None or modo == 3:
        return

    if modo == 0:
        resultado = consultar_vulnerabilidades(ativos)
    elif modo == 1:
        identificador = ler_id_para_operacao("ID do ativo")
        if identificador is None:
            return
        ativo = consultar_por_id(ativos, identificador)
        if ativo is None:
            mostrar_erro("Ativo não encontrado.")
            return
        resultado = [(ativo, vulnerabilidade) for vulnerabilidade in ativo.vulnerabilidades]
    else:
        resultado = consultar_vulnerabilidades(ativos,
            ler_texto("CVE exato (vazio = todos): ", False),
            escolher_item("Prioridade: ", SEVERIDADES, True),
            escolher_item("Status: ", STATUS, True))

    navegar_vulnerabilidades(resultado)


def atualizar_vulnerabilidade_tela(ativos):
    print()
    mostrar_titulo("Atualização de vulnerabilidade")

    def ler_id_existente(valores, anterior, preenchido):
        while True:
            identificador = ler_inteiro_formulario("ID do ativo afetado", anterior, preenchido)
            if identificador is VOLTAR:
                return VOLTAR
            if consultar_por_id(ativos, identificador) is not None:
                if anterior is not None and identificador != anterior:
                    valores.clear()
                return identificador
            mostrar_erro("Ativo não encontrado.")

    def ler_cve_existente(valores, anterior, preenchido):
        while True:
            cve = ler_validado_formulario(
                "CVE da vulnerabilidade", validar_cve, anterior, preenchido
            )
            if cve is VOLTAR:
                return VOLTAR
            ativo = consultar_por_id(ativos, valores["identificador"])
            if buscar_vulnerabilidade(ativo, cve) is not None:
                if anterior is not None and cve != anterior:
                    # Um novo CVE é outro registro: não reaproveitar seus campos.
                    identificador_atual = valores["identificador"]
                    valores.clear()
                    valores["identificador"] = identificador_atual
                return cve
            mostrar_erro("Vulnerabilidade não encontrada para este ativo.")

    dados = preencher_formulario([
        ("identificador", ler_id_existente),
        ("cve", ler_cve_existente),
        ("descricao", lambda valores, anterior, preenchido: ler_texto_formulario(
            "Nova descrição", False, anterior, preenchido
        )),
        ("prioridade", lambda valores, anterior, preenchido: escolher_item_atualizacao(
            "Nova prioridade:", SEVERIDADES, anterior, preenchido
        )),
        ("tratamento", lambda valores, anterior, preenchido: ler_texto_formulario(
            "Novo tratamento", False, anterior, preenchido
        )),
        ("status", lambda valores, anterior, preenchido: escolher_item_atualizacao(
            "Novo status:", STATUS, anterior, preenchido
        )),
        ("verificacao", lambda valores, anterior, preenchido: ler_verificacao_formulario(
            valores, "Nova verificação", anterior, preenchido, False,
            buscar_vulnerabilidade(
                consultar_por_id(ativos, valores["identificador"]), valores["cve"]
            ).verificacao
        )),
    ])
    if dados is None:
        return False
    if not any([dados["descricao"], dados["prioridade"], dados["tratamento"],
                dados["status"], dados["verificacao"]]):
        mostrar_aviso("Nenhum campo foi alterado.")
        return False
    try:
        atualizar_vulnerabilidade(
            ativos, dados["identificador"], dados["cve"], dados["descricao"],
            dados["prioridade"], dados["tratamento"], dados["status"],
            dados["verificacao"]
        )
        mostrar_sucesso("Vulnerabilidade atualizada com sucesso.")
        return True
    except DadosInvalidosError as erro:
        mostrar_erro(str(erro))
        return False


def remover_vulnerabilidade_tela(ativos):
    print()
    mostrar_titulo("Remoção de vulnerabilidade")
    identificador = ler_id_para_operacao("ID do ativo afetado")
    if identificador is None:
        return False
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        mostrar_erro("Ativo não encontrado.")
        return False
    cve = ler_validado_formulario("CVE da vulnerabilidade", validar_cve)
    if cve is VOLTAR:
        mostrar_aviso("Operação cancelada.")
        return False
    vulnerabilidade = buscar_vulnerabilidade(ativo, cve)
    if vulnerabilidade is None:
        mostrar_erro("Vulnerabilidade não encontrada para este ativo.")
        return False
    print(f"Confirme o alvo: {vulnerabilidade.cve} - {vulnerabilidade.descricao}.")
    try:
        if excluir_vulnerabilidade(
                ativos, identificador, cve,
                confirmar_remocao()):
            mostrar_sucesso("Vulnerabilidade removida com sucesso.")
            return True
        mostrar_aviso("Remoção cancelada.")
        return False
    except DadosInvalidosError as erro:
        mostrar_erro(str(erro))
        return False


def mostrar_resumo(ativos):
    total = sum(len(ativo.vulnerabilidades) for ativo in ativos.values())
    print()
    mostrar_titulo("Resumo do inventário")
    print(f"Total de ativos cadastrados: {len(ativos)}")
    print(f"Total de vulnerabilidades cadastradas: {total}")


def mostrar_menu():
    """Exibe o menu principal e devolve o código escolhido pelas setas."""
    opcoes_menu = [
        ("Cadastrar ativo", "1"),
        ("Listar ativos", "2"),
        ("Buscar ativo", "3"),
        ("Atualizar ativo", "4"),
        ("Remover ativo", "5"),
        ("Cadastrar vulnerabilidade", "6"),
        ("Consultar vulnerabilidades", "7"),
        ("Atualizar vulnerabilidade", "8"),
        ("Remover vulnerabilidade", "9"),
        ("Mostrar resumo do inventário", "10"),
        ("Sair", "0"),
    ]
    print()
    mostrar_titulo("Inventário de ativos e vulnerabilidades")
    print(colorir("MENU PRINCIPAL", "1;36"))
    indice = escolher_com_setas(
        "Escolha uma ação:",
        [f"{codigo:>2} | {descricao}" for descricao, codigo in opcoes_menu],
    )
    return opcoes_menu[indice][1]


def executar_programa(ativos, caminho_dados):
    mostrar_sucesso(f"Base carregada: {len(ativos)} ativo(s).")
    while True:
        opcao = mostrar_menu()
        alterou = False
        if opcao == "1":
            alterou = cadastrar_ativo_tela(ativos)
        elif opcao == "2":
            listar_ativos_tela(ativos)
        elif opcao == "3":
            buscar_ativo_tela(ativos)
        elif opcao == "4":
            alterou = atualizar_ativo_tela(ativos)
        elif opcao == "5":
            alterou = remover_ativo_tela(ativos)
        elif opcao == "6":
            alterou = cadastrar_vulnerabilidade_tela(ativos)
        elif opcao == "7":
            consultar_vulnerabilidades_tela(ativos)
        elif opcao == "8":
            alterou = atualizar_vulnerabilidade_tela(ativos)
        elif opcao == "9":
            alterou = remover_vulnerabilidade_tela(ativos)
        elif opcao == "10":
            mostrar_resumo(ativos)
        elif opcao == "0":
            if salvar_com_aviso(ativos, caminho_dados):
                mostrar_sucesso("Programa encerrado.")
                break
            if ler_sim_ou_nao("Deseja sair sem salvar?"):
                mostrar_aviso("Programa encerrado sem salvar as alterações mais recentes.")
                break
        else:
            mostrar_erro("Opção inválida. Escolha uma opção do menu.")
        if alterou:
            salvar_com_aviso(ativos, caminho_dados)


def salvar_com_aviso(ativos, caminho_dados):
    """Salva a base e deixa claro quando a alteração não foi gravada."""
    if salvar_ativos(ativos, caminho_dados):
        return True
    mostrar_erro("Não foi possível salvar. Os dados continuam abertos; tente sair novamente após corrigir o acesso ao arquivo.")
    return False
