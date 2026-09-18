"""Projeto final da Sprint 1: inventário de ativos e vulnerabilidades."""

import json
import os
from enum import IntEnum


class TipoAtivo(IntEnum):
    NOTEBOOK = 1
    SERVIDOR = 2
    ROTEADOR = 3
    APLICACAO_WEB = 4
    BANCO_DE_DADOS = 5
    SOFTWARE_LICENCIADO = 6


ARQUIVO_DADOS = "dados/inventario.json"
SEVERIDADES = ["Baixa", "Média", "Alta", "Crítica"]
STATUS = ["Aberta", "Em tratamento", "Corrigida", "Aceita como risco"]


def mostrar_linha():
    print("-" * 65)


def ler_texto(mensagem, obrigatorio=True):
    while True:
        texto = input(mensagem).strip()
        if texto or not obrigatorio:
            return texto
        print("Este campo não pode ficar vazio.")


def ler_inteiro(mensagem):
    while True:
        try:
            numero = int(input(mensagem).strip())
            if numero > 0:
                return numero
            print("Digite um número maior que zero.")
        except ValueError:
            print("Digite somente um número inteiro válido.")


def ler_sim_ou_nao(mensagem):
    while True:
        resposta = input(mensagem).strip().lower()
        if resposta == "s" or resposta == "sim":
            return True
        if resposta == "n" or resposta == "nao" or resposta == "não":
            return False
        print("Resposta inválida. Digite s para sim ou n para não.")


def escolher_item(mensagem, opcoes):
    while True:
        resposta = ler_texto(mensagem)
        for opcao in opcoes:
            if resposta.lower() == opcao.lower():
                return opcao
        print("Opção inválida. Escolha uma das opções mostradas.")


def escolher_tipo_ativo():
    print("Tipos de ativo:")
    for tipo in TipoAtivo:
        nome = tipo.name.replace("_", " ").title()
        print(f"{tipo.value} - {nome}")

    while True:
        codigo = ler_inteiro("Código do tipo: ")
        try:
            tipo = TipoAtivo(codigo)
            return tipo.value
        except ValueError:
            print("Código inexistente. Escolha um tipo mostrado na lista.")


def nome_do_tipo(codigo):
    try:
        return TipoAtivo(codigo).name.replace("_", " ").title()
    except ValueError:
        return "Tipo não identificado"


def carregar_ativos():
    if not os.path.exists(ARQUIVO_DADOS):
        return {}

    try:
        with open(ARQUIVO_DADOS, "r", encoding="utf-8") as arquivo:
            dados = json.load(arquivo)

        ativos = {}
        for identificador, ativo in dados.items():
            ativos[int(identificador)] = ativo
        return ativos
    except (OSError, json.JSONDecodeError, ValueError):
        print("Não foi possível ler o arquivo de dados. Uma base vazia será usada.")
        return {}


def salvar_ativos(ativos):
    try:
        os.makedirs("dados", exist_ok=True)
        with open(ARQUIVO_DADOS, "w", encoding="utf-8") as arquivo:
            json.dump(ativos, arquivo, ensure_ascii=False, indent=2)
        print("Dados salvos com sucesso.")
    except OSError:
        print("Erro ao salvar os dados no arquivo.")


def criar_vulnerabilidade():
    print("\nCadastro de vulnerabilidade")
    vulnerabilidade = {}
    vulnerabilidade["descricao"] = ler_texto("Descrição: ")
    vulnerabilidade["categoria"] = ler_texto("Categoria ou tipo: ")
    print("Severidades: " + ", ".join(SEVERIDADES))
    vulnerabilidade["severidade"] = escolher_item("Severidade: ", SEVERIDADES)
    print("Status: " + ", ".join(STATUS))
    vulnerabilidade["status"] = escolher_item("Status de tratamento: ", STATUS)
    return vulnerabilidade


def mostrar_vulnerabilidades(ativo):
    vulnerabilidades = ativo["vulnerabilidades"]
    print("Vulnerabilidades:")
    if len(vulnerabilidades) == 0:
        print("  Este ativo não possui vulnerabilidades registradas.")
        return

    numero = 1
    for vulnerabilidade in vulnerabilidades:
        print(f"  {numero}. {vulnerabilidade['descricao']}")
        print(f"     Categoria: {vulnerabilidade['categoria']}")
        print(f"     Severidade: {vulnerabilidade['severidade']}")
        print(f"     Status: {vulnerabilidade['status']}")
        numero += 1


def mostrar_ativo(ativo, mostrar_vulnerabilidades_do_ativo=True):
    mostrar_linha()
    print(f"ID: {ativo['id']}")
    print(f"Nome ou hostname: {ativo['nome']}")
    print(f"Responsável: {ativo['responsavel']}")
    print(f"Setor ou localização: {ativo['localizacao']}")
    print(f"Tipo: {nome_do_tipo(ativo['tipo'])} ({ativo['tipo']})")
    if mostrar_vulnerabilidades_do_ativo:
        mostrar_vulnerabilidades(ativo)


def cadastrar_ativo(ativos):
    print("\nCadastro de ativo")
    identificador = ler_inteiro("ID único do ativo: ")

    if identificador in ativos:
        print("Já existe um ativo com esse ID.")
        return

    ativo = {}
    ativo["id"] = identificador
    ativo["nome"] = ler_texto("Nome ou hostname: ")
    ativo["responsavel"] = ler_texto("Responsável: ")
    ativo["localizacao"] = ler_texto("Setor ou localização: ")
    ativo["tipo"] = escolher_tipo_ativo()
    ativo["vulnerabilidades"] = []

    while ler_sim_ou_nao("Deseja cadastrar uma vulnerabilidade inicial? (s/n): "):
        ativo["vulnerabilidades"].append(criar_vulnerabilidade())

    ativos[identificador] = ativo
    print("Ativo cadastrado com sucesso.")


def listar_ativos(ativos):
    if len(ativos) == 0:
        print("Não há ativos cadastrados.")
        return

    for identificador in sorted(ativos):
        mostrar_ativo(ativos[identificador], False)


def buscar_ativo(ativos):
    print("\n1 - Buscar por ID")
    print("2 - Buscar por nome ou hostname")
    escolha = ler_texto("Escolha: ")

    if escolha == "1":
        identificador = ler_inteiro("ID do ativo: ")
        if identificador in ativos:
            mostrar_ativo(ativos[identificador])
        else:
            print("Ativo não encontrado.")
    elif escolha == "2":
        termo = ler_texto("Nome ou hostname: ").lower()
        encontrou = False
        for ativo in ativos.values():
            if termo in ativo["nome"].lower():
                mostrar_ativo(ativo)
                encontrou = True
        if not encontrou:
            print("Nenhum ativo encontrado.")
    else:
        print("Opção inválida.")


def atualizar_ativo(ativos):
    identificador = ler_inteiro("ID do ativo que será atualizado: ")
    if identificador not in ativos:
        print("Ativo não encontrado.")
        return

    ativo = ativos[identificador]
    print("Deixe em branco para manter o valor atual.")
    nome = ler_texto(f"Nome ou hostname [{ativo['nome']}]: ", False)
    responsavel = ler_texto(f"Responsável [{ativo['responsavel']}]: ", False)
    localizacao = ler_texto(f"Setor ou localização [{ativo['localizacao']}]: ", False)

    if nome:
        ativo["nome"] = nome
    if responsavel:
        ativo["responsavel"] = responsavel
    if localizacao:
        ativo["localizacao"] = localizacao
    if ler_sim_ou_nao("Deseja alterar o tipo do ativo? (s/n): "):
        ativo["tipo"] = escolher_tipo_ativo()

    print("Ativo atualizado com sucesso.")


def remover_ativo(ativos):
    identificador = ler_inteiro("ID do ativo que será removido: ")
    if identificador not in ativos:
        print("Ativo não encontrado.")
        return

    ativo = ativos[identificador]
    print(f"O ativo {ativo['nome']} e suas vulnerabilidades serão removidos.")
    if ler_texto("Digite SIM para confirmar: ").upper() == "SIM":
        del ativos[identificador]
        print("Ativo removido com sucesso.")
    else:
        print("Remoção cancelada.")


def cadastrar_vulnerabilidade(ativos):
    identificador = ler_inteiro("ID do ativo: ")
    if identificador not in ativos:
        print("Ativo não encontrado.")
        return

    vulnerabilidade = criar_vulnerabilidade()
    ativos[identificador]["vulnerabilidades"].append(vulnerabilidade)
    print("Vulnerabilidade cadastrada com sucesso.")


def visualizar_vulnerabilidades(ativos):
    identificador = ler_inteiro("ID do ativo: ")
    if identificador not in ativos:
        print("Ativo não encontrado.")
        return

    mostrar_ativo(ativos[identificador])


def mostrar_menu():
    mostrar_linha()
    print("INVENTÁRIO DE ATIVOS E VULNERABILIDADES")
    print("1 - Cadastrar ativo")
    print("2 - Listar ativos")
    print("3 - Buscar ativo")
    print("4 - Atualizar ativo")
    print("5 - Remover ativo")
    print("6 - Cadastrar vulnerabilidade")
    print("7 - Visualizar vulnerabilidades de um ativo")
    print("8 - Salvar dados")
    print("0 - Sair")


def executar_programa():
    ativos = carregar_ativos()
    print(f"Base carregada: {len(ativos)} ativo(s).")

    while True:
        mostrar_menu()
        opcao = ler_texto("Escolha uma opção: ")

        if opcao == "1":
            cadastrar_ativo(ativos)
            salvar_ativos(ativos)
        elif opcao == "2":
            listar_ativos(ativos)
        elif opcao == "3":
            buscar_ativo(ativos)
        elif opcao == "4":
            atualizar_ativo(ativos)
            salvar_ativos(ativos)
        elif opcao == "5":
            remover_ativo(ativos)
            salvar_ativos(ativos)
        elif opcao == "6":
            cadastrar_vulnerabilidade(ativos)
            salvar_ativos(ativos)
        elif opcao == "7":
            visualizar_vulnerabilidades(ativos)
        elif opcao == "8":
            salvar_ativos(ativos)
        elif opcao == "0":
            salvar_ativos(ativos)
            print("Programa encerrado.")
            break
        else:
            print("Opção inválida. Escolha uma opção do menu.")


executar_programa()

