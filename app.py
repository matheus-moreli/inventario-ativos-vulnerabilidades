"""Projeto final em Python da Sprint 1: inventário de ativos e vulnerabilidades."""

# json transforma os dicionários e listas do Python em um arquivo persistente.
import json
# os permite verificar a existência do arquivo e criar a pasta de dados.
import os
# IntEnum cria uma lista de tipos com nome e código inteiro.
from enum import IntEnum


class TipoAtivo(IntEnum):
    # Os códigos são fixos para que o programa salve um número simples no JSON,
    # mas ainda consiga mostrar um nome legível para a pessoa usuária.
    NOTEBOOK = 1
    SERVIDOR = 2
    ROTEADOR = 3
    APLICACAO_WEB = 4
    BANCO_DE_DADOS = 5
    SOFTWARE_LICENCIADO = 6


# Constantes: evitar repetir textos importantes diminui o risco de digitar
# caminhos ou opções diferentes em partes distintas do programa.
ARQUIVO_DADOS = "dados/inventario.json"
# Estas listas limitam as escolhas permitidas ao cadastrar uma vulnerabilidade.
SEVERIDADES = ["Baixa", "Média", "Alta", "Crítica"]
STATUS = ["Aberta", "Em tratamento", "Corrigida", "Aceita como risco"]


class DadosInvalidosError(Exception):
    # Uma exceção própria deixa claro que o erro veio de uma regra do projeto,
    # e não apenas de uma falha genérica de leitura do arquivo.
    """Indica que o arquivo JSON não tem o formato esperado."""


def mostrar_linha():
    # Uma função pequena evita repetir a mesma linha decorativa em vários locais.
    print("-" * 65)


def ler_texto(mensagem, obrigatorio=True):
    # O while mantém a pergunta aberta até que a entrada respeite a regra.
    while True:
        # strip remove espaços extras; assim, somente espaços não contam como texto.
        texto = input(mensagem).strip()
        # Quando o campo é opcional, a string vazia é aceita para permitir
        # manter o valor anterior durante a atualização de um ativo.
        if texto or not obrigatorio:
            return texto
        print("Este campo não pode ficar vazio.")


def ler_inteiro(mensagem):
    # A conversão para int pode falhar; por isso ela fica protegida pelo try.
    while True:
        try:
            numero = int(input(mensagem).strip())
            # IDs e códigos de tipo não devem ser zero nem negativos.
            if numero > 0:
                return numero
            print("Digite um número maior que zero.")
        except ValueError:
            print("Digite somente um número inteiro válido.")


def ler_sim_ou_nao(mensagem):
    while True:
        # lower permite aceitar "S", "s", "SIM" e "sim" da mesma forma.
        resposta = input(mensagem).strip().lower()
        if resposta == "s" or resposta == "sim":
            return True
        if resposta == "n" or resposta == "nao" or resposta == "não":
            return False
        print("Resposta inválida. Digite s para sim ou n para não.")


def escolher_item(mensagem, opcoes):
    # Esta função é reutilizada para severidade e status, que possuem listas
    # diferentes, mas seguem a mesma regra de validação.
    while True:
        resposta = ler_texto(mensagem)
        # O for percorre todas as opções até encontrar uma que corresponda.
        for opcao in opcoes:
            # A comparação ignora maiúsculas e minúsculas, mas retorna a versão
            # original da lista para manter os dados salvos padronizados.
            if resposta.lower() == opcao.lower():
                return opcao
        print("Opção inválida. Escolha uma das opções mostradas.")


def escolher_tipo_ativo():
    print("Tipos de ativo:")
    # Percorrer o Enum evita duplicar manualmente os tipos no menu.
    for tipo in TipoAtivo:
        # name é o nome técnico do Enum; replace e title o tornam legível.
        nome = tipo.name.replace("_", " ").title()
        print(f"{tipo.value} - {nome}")

    while True:
        codigo = ler_inteiro("Código do tipo: ")
        try:
            # Tentar criar o Enum confirma que o código digitado existe.
            tipo = TipoAtivo(codigo)
            # Guardamos apenas o valor inteiro para facilitar a persistência JSON.
            return tipo.value
        except ValueError:
            print("Código inexistente. Escolha um tipo mostrado na lista.")


def nome_do_tipo(codigo):
    try:
        # Faz o caminho contrário: código salvo no JSON para nome exibido na tela.
        return TipoAtivo(codigo).name.replace("_", " ").title()
    except ValueError:
        # A mensagem evita encerrar o programa se um arquivo antigo tiver código inválido.
        return "Tipo não identificado"


def carregar_ativos():
    # Na primeira execução o arquivo ainda não existe; uma base vazia é normal.
    if not os.path.exists(ARQUIVO_DADOS):
        return {}

    try:
        with open(ARQUIVO_DADOS, "r", encoding="utf-8") as arquivo:
            # load transforma o JSON de volta em listas e dicionários Python.
            dados = json.load(arquivo)

        # A base inteira precisa ser um dicionário com IDs como chaves.
        if not isinstance(dados, dict):
            raise DadosInvalidosError("A base deve conter ativos organizados por ID.")

    except (OSError, json.JSONDecodeError, ValueError, DadosInvalidosError):
        # O programa continua funcionando mesmo com arquivo ausente, corrompido
        # ou incompatível, em vez de encerrar por causa de uma exceção.
        print("Não foi possível ler o arquivo de dados. Uma base vazia será usada.")
        return {}
    else:
        ativos = {}
        for identificador, ativo in dados.items():
            # JSON guarda chaves como texto; converter restaura o ID como int.
            ativos[int(identificador)] = ativo
        return ativos


def salvar_ativos(ativos):
    try:
        # exist_ok=True não gera erro quando a pasta dados já existe.
        os.makedirs("dados", exist_ok=True)
        with open(ARQUIVO_DADOS, "w", encoding="utf-8") as arquivo:
            # indent organiza o arquivo; ensure_ascii=False preserva acentos.
            json.dump(ativos, arquivo, ensure_ascii=False, indent=2)
        print("Dados salvos com sucesso.")
    except OSError:
        print("Erro ao salvar os dados no arquivo.")


def criar_vulnerabilidade():
    print("\nCadastro de vulnerabilidade")
    # Cada vulnerabilidade é um dicionário para manter os campos nomeados.
    vulnerabilidade = {}
    vulnerabilidade["descricao"] = ler_texto("Descrição: ")
    vulnerabilidade["categoria"] = ler_texto("Categoria ou tipo: ")
    print("Severidades: " + ", ".join(SEVERIDADES))
    vulnerabilidade["severidade"] = escolher_item("Severidade: ", SEVERIDADES)
    print("Status: " + ", ".join(STATUS))
    vulnerabilidade["status"] = escolher_item("Status de tratamento: ", STATUS)
    return vulnerabilidade


def mostrar_vulnerabilidades(ativo):
    # A lista pertence ao ativo: vulnerabilidades não existem soltas na base.
    vulnerabilidades = ativo["vulnerabilidades"]
    print("Vulnerabilidades:")
    if len(vulnerabilidades) == 0:
        print("  Este ativo não possui vulnerabilidades registradas.")
        return

    # A numeração serve apenas para exibição; ela não é um ID da vulnerabilidade.
    numero = 1
    for vulnerabilidade in vulnerabilidades:
        print(f"  {numero}. {vulnerabilidade['descricao']}")
        print(f"     Categoria: {vulnerabilidade['categoria']}")
        print(f"     Severidade: {vulnerabilidade['severidade']}")
        print(f"     Status: {vulnerabilidade['status']}")
        numero += 1


def mostrar_ativo(ativo, mostrar_vulnerabilidades_do_ativo=True):
    # O parâmetro permite reutilizar esta função: a listagem geral mostra apenas
    # dados principais, enquanto a busca pode exibir os detalhes completos.
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
        # A chave do dicionário é o ID, então esta verificação impede duplicidade.
        print("Já existe um ativo com esse ID.")
        return

    # Montamos o registro antes de colocá-lo na base, para só salvar um ativo completo.
    ativo = {}
    ativo["id"] = identificador
    ativo["nome"] = ler_texto("Nome ou hostname: ")
    ativo["responsavel"] = ler_texto("Responsável: ")
    ativo["localizacao"] = ler_texto("Setor ou localização: ")
    ativo["tipo"] = escolher_tipo_ativo()
    ativo["vulnerabilidades"] = []

    # O while permite cadastrar zero, uma ou várias vulnerabilidades logo no início.
    while ler_sim_ou_nao("Deseja cadastrar uma vulnerabilidade inicial? (s/n): "):
        ativo["vulnerabilidades"].append(criar_vulnerabilidade())

    # A inserção final usa o ID como chave para permitir busca direta depois.
    ativos[identificador] = ativo
    print("Ativo cadastrado com sucesso.")


def listar_ativos(ativos):
    if len(ativos) == 0:
        print("Não há ativos cadastrados.")
        return

    # sorted deixa a listagem previsível, em ordem numérica crescente de ID.
    for identificador in sorted(ativos):
        mostrar_ativo(ativos[identificador], False)


def mostrar_resumo(ativos):
    total_vulnerabilidades = 0
    # values entrega cada registro; somamos o tamanho da lista de cada ativo.
    for ativo in ativos.values():
        total_vulnerabilidades += len(ativo["vulnerabilidades"])

    mostrar_linha()
    print(f"Total de ativos cadastrados: {len(ativos)}")
    print(f"Total de vulnerabilidades cadastradas: {total_vulnerabilidades}")


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
        # lower padroniza a busca, permitindo encontrar "srv" e "SRV".
        termo = ler_texto("Nome ou hostname: ").lower()
        # A variável indica se algum registro foi mostrado durante o for.
        encontrou = False
        for ativo in ativos.values():
            # in permite busca parcial: "arquivos" encontra "SRV-ARQUIVOS".
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

    # Pegamos uma referência ao dicionário já guardado; as alterações nele
    # atualizam o mesmo ativo dentro da base.
    ativo = ativos[identificador]
    print("Deixe em branco para manter o valor atual.")
    nome = ler_texto(f"Nome ou hostname [{ativo['nome']}]: ", False)
    responsavel = ler_texto(f"Responsável [{ativo['responsavel']}]: ", False)
    localizacao = ler_texto(f"Setor ou localização [{ativo['localizacao']}]: ", False)

    # Cada if só substitui o campo quando a pessoa digitou algo novo.
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

    # O aviso menciona as vulnerabilidades porque elas estão dentro do ativo e
    # serão removidas junto com o registro pai.
    ativo = ativos[identificador]
    print(f"O ativo {ativo['nome']} e suas vulnerabilidades serão removidos.")
    if ler_texto("Digite SIM para confirmar: ").upper() == "SIM":
        # del remove a chave e todo o dicionário associado a ela.
        del ativos[identificador]
        print("Ativo removido com sucesso.")
    else:
        print("Remoção cancelada.")


def cadastrar_vulnerabilidade(ativos):
    identificador = ler_inteiro("ID do ativo: ")
    if identificador not in ativos:
        print("Ativo não encontrado.")
        return

    # Só criamos a vulnerabilidade depois de confirmar que o ativo existe.
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
    # O menu é mantido em uma função própria para ser repetido a cada volta do laço principal.
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
    print("9 - Mostrar resumo do inventário")
    print("0 - Sair")


def executar_programa():
    # Os dados são carregados uma vez e o mesmo dicionário é compartilhado com
    # todas as funções de cadastro, busca, atualização e remoção.
    ativos = carregar_ativos()
    print(f"Base carregada: {len(ativos)} ativo(s).")

    while True:
        mostrar_menu()
        opcao = ler_texto("Escolha uma opção: ")

        if opcao == "1":
            cadastrar_ativo(ativos)
            # Após uma mudança, salvar imediatamente reduz a chance de perder dados.
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
        elif opcao == "9":
            mostrar_resumo(ativos)
        elif opcao == "0":
            # Salvar novamente ao sair garante que a última alteração também foi gravada.
            salvar_ativos(ativos)
            print("Programa encerrado.")
            break
        else:
            print("Opção inválida. Escolha uma opção do menu.")


# Este ponto inicia o programa depois que todas as funções foram definidas.
executar_programa()

