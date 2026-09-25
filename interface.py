"""Entradas e saídas do terminal. As regras estão em inventario.py."""

from inventario import (DadosInvalidosError, atualizar_ativo, atualizar_vulnerabilidade,
                        buscar_vulnerabilidade, cadastrar_ativo,
                        cadastrar_vulnerabilidade, consultar_por_id,
                        consultar_vulnerabilidades, excluir_ativo,
                        excluir_vulnerabilidade, filtrar_ativos, validar_cve,
                        validar_cwe, validar_cvss, validar_data_fonte)
from modelos import CRITICIDADES, SEVERIDADES, STATUS, TipoAtivo
from persistencia import salvar_ativos


def mostrar_linha():
    # Uma função curta mantém o mesmo separador em todas as telas.
    print("-" * 65)


def ler_texto(mensagem, obrigatorio=True):
    # A validação na tela evita enviar campos vazios à regra de negócio.
    while True:
        texto = input(mensagem).strip()
        if texto or not obrigatorio:
            return texto
        print("Este campo não pode ficar vazio.")


def ler_inteiro(mensagem):
    # try impede que uma conversão inválida encerre o programa.
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
        if resposta in ["s", "sim"]:
            return True
        if resposta in ["n", "nao", "não"]:
            return False
        print("Resposta inválida. Digite s para sim ou n para não.")


def ler_cve(mensagem):
    """Valida o CVE logo após a digitação, sem perder as outras respostas."""
    while True:
        try:
            return validar_cve(ler_texto(mensagem))
        except DadosInvalidosError as erro:
            print(erro)


def ler_cwe(mensagem):
    """Valida o CWE logo após a digitação."""
    while True:
        try:
            return validar_cwe(ler_texto(mensagem))
        except DadosInvalidosError as erro:
            print(erro)


def ler_cvss(mensagem):
    """Lê uma nota CVSS válida no intervalo de 0.0 a 10.0."""
    while True:
        try:
            return validar_cvss(ler_texto(mensagem))
        except DadosInvalidosError as erro:
            print(erro)


def ler_data_fonte(mensagem):
    """Mantém a data da fonte no formato dd/mm/aaaa anunciado pelo menu."""
    while True:
        try:
            return validar_data_fonte(ler_texto(mensagem))
        except DadosInvalidosError as erro:
            print(erro)


def escolher_item(mensagem, opcoes, permitir_vazio=False):
    # Devolve a opção da lista, mantendo os dados salvos padronizados.
    print("Opções: " + ", ".join(opcoes))
    while True:
        resposta = ler_texto(mensagem, not permitir_vazio)
        if permitir_vazio and not resposta:
            return None
        for opcao in opcoes:
            if resposta.lower() == opcao.lower():
                return opcao
        print("Opção inválida. Escolha uma das opções mostradas.")


def escolher_tipo_ativo(permitir_vazio=False):
    print("Tipos de ativo:")
    for tipo in TipoAtivo:
        print(f"{tipo.value} - {tipo.name.replace('_', ' ').title()}")
    while True:
        resposta = ler_texto("Código do tipo: ", not permitir_vazio)
        if permitir_vazio and not resposta:
            return None
        try:
            return TipoAtivo(int(resposta)).value
        except (ValueError, TypeError):
            print("Código inexistente. Escolha um tipo mostrado na lista.")


def nome_do_tipo(codigo):
    try:
        return TipoAtivo(codigo).name.replace("_", " ").title()
    except ValueError:
        return "Tipo não identificado"


def mostrar_vulnerabilidades(ativo):
    print("Vulnerabilidades:")
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
    mostrar_linha()
    print(f"ID: {ativo.id}")
    print(f"Nome ou hostname: {ativo.nome}")
    print(f"Responsável: {ativo.responsavel}")
    print(f"Setor ou localização: {ativo.localizacao}")
    print(f"Tipo: {nome_do_tipo(ativo.tipo)} ({ativo.tipo})")
    print(f"Criticidade: {ativo.criticidade}")
    if mostrar_detalhes:
        mostrar_vulnerabilidades(ativo)
        print("Histórico:")
        for evento in ativo.historico or ["Nenhuma alteração registrada."]:
            print(f"  - {evento}")


def cadastrar_ativo_tela(ativos):
    print("\nCadastro de ativo")
    identificador = ler_inteiro("ID único do ativo: ")
    if consultar_por_id(ativos, identificador) is not None:
        print("Já existe um ativo com esse ID.")
        return False
    try:
        ativo = cadastrar_ativo(ativos, identificador,
            ler_texto("Nome ou hostname: "), ler_texto("Responsável: "),
            ler_texto("Setor ou localização: "), escolher_tipo_ativo(),
            escolher_item("Criticidade: ", CRITICIDADES))
        print(f"Ativo {ativo.id} cadastrado com sucesso.")
        return True
    except DadosInvalidosError as erro:
        print(erro)
        return False


def listar_ativos_tela(ativos):
    if not ativos:
        print("Não há ativos cadastrados.")
        return
    for identificador in sorted(ativos):
        mostrar_ativo(ativos[identificador], False)


def buscar_ativo_tela(ativos):
    print("\n1 - Buscar por ID")
    print("2 - Filtrar por nome, tipo ou criticidade")
    escolha = ler_texto("Escolha: ")
    if escolha == "1":
        ativo = consultar_por_id(ativos, ler_inteiro("ID do ativo: "))
        if ativo is None:
            print("Ativo não encontrado.")
        else:
            mostrar_ativo(ativo)
    elif escolha == "2":
        termo = ler_texto("Nome ou hostname (vazio = todos): ", False)
        tipo = escolher_tipo_ativo() if ler_sim_ou_nao("Filtrar por tipo? (s/n): ") else None
        criticidade = escolher_item("Criticidade: ", CRITICIDADES) if ler_sim_ou_nao("Filtrar por criticidade? (s/n): ") else None
        resultado = filtrar_ativos(ativos, termo, tipo, criticidade)
        if not resultado:
            print("Nenhum ativo encontrado.")
        for ativo in resultado:
            mostrar_ativo(ativo, False)
    else:
        print("Opção inválida.")


def atualizar_ativo_tela(ativos):
    identificador = ler_inteiro("ID do ativo que será atualizado: ")
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        print("Ativo não encontrado.")
        return False
    print("Deixe em branco para manter o valor atual.")
    nome = ler_texto(f"Nome ou hostname [{ativo.nome}]: ", False)
    responsavel = ler_texto(f"Responsável [{ativo.responsavel}]: ", False)
    localizacao = ler_texto(f"Setor ou localização [{ativo.localizacao}]: ", False)
    tipo = escolher_tipo_ativo(True)
    criticidade = escolher_item("Criticidade: ", CRITICIDADES, True)
    if not any([nome, responsavel, localizacao, tipo is not None, criticidade is not None]):
        print("Nenhum campo foi alterado.")
        return False
    try:
        atualizar_ativo(ativos, identificador, nome, responsavel, localizacao, tipo, criticidade)
        print("Ativo atualizado com sucesso. A alteração está no histórico.")
        return True
    except DadosInvalidosError as erro:
        print(erro)
        return False


def remover_ativo_tela(ativos):
    identificador = ler_inteiro("ID do ativo que será removido: ")
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        print("Ativo não encontrado.")
        return False
    print(f"Confirme o alvo: ID {ativo.id} - {ativo.nome}.")
    print("Política: a exclusão remove o ativo e as vulnerabilidades associadas.")
    try:
        if excluir_ativo(ativos, identificador, ler_texto("Digite SIM para confirmar: ").upper() == "SIM"):
            print("Ativo removido com sucesso.")
            return True
        print("Remoção cancelada.")
        return False
    except DadosInvalidosError as erro:
        print(erro)
        return False


def cadastrar_vulnerabilidade_tela(ativos):
    print("\nCadastro de vulnerabilidade")
    identificador = ler_inteiro("ID do ativo afetado: ")
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        print("Ativo não encontrado.")
        return False
    cve = ler_cve("CVE (ex.: CVE-2024-1234): ")
    if buscar_vulnerabilidade(ativo, cve) is not None:
        print("Esta vulnerabilidade já foi cadastrada para o ativo.")
        return False
    try:
        vulnerabilidade = cadastrar_vulnerabilidade(ativos, identificador, cve,
            ler_cwe("CWE (ex.: CWE-79): "), ler_cvss("Nota CVSS (0.0 a 10.0): "),
            ler_texto("Descrição: "), ler_texto("Fonte verificável (URL ou órgão): "),
            ler_data_fonte("Data da fonte (dd/mm/aaaa): "),
            ler_texto("Impacto no ativo: "), escolher_item("Prioridade: ", SEVERIDADES),
            ler_texto("Tratamento planejado: "), escolher_item("Status: ", STATUS),
            ler_texto("Como será verificado o tratamento: "))
        print(f"Vulnerabilidade {vulnerabilidade.cve} cadastrada com sucesso.")
        return True
    except DadosInvalidosError as erro:
        print(erro)
        return False


def consultar_vulnerabilidades_tela(ativos):
    print("\nConsulta de vulnerabilidades")
    resultado = consultar_vulnerabilidades(ativos,
        ler_texto("CVE exato (vazio = todos): ", False),
        escolher_item("Prioridade: ", SEVERIDADES, True),
        escolher_item("Status: ", STATUS, True))
    if not resultado:
        print("Nenhuma vulnerabilidade encontrada.")
        return
    for ativo, vulnerabilidade in resultado:
        mostrar_linha()
        print(f"Ativo afetado: ID {ativo.id} - {ativo.nome}")
        print(f"{vulnerabilidade.cve} | CVSS {vulnerabilidade.cvss:.1f} | {vulnerabilidade.prioridade}")
        print(f"Fonte: {vulnerabilidade.fonte} ({vulnerabilidade.data_fonte})")
        print(f"Status: {vulnerabilidade.status} | Verificação: {vulnerabilidade.verificacao}")


def atualizar_vulnerabilidade_tela(ativos):
    print("\nAtualização de vulnerabilidade")
    identificador = ler_inteiro("ID do ativo afetado: ")
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        print("Ativo não encontrado.")
        return False
    cve = ler_cve("CVE da vulnerabilidade: ")
    if buscar_vulnerabilidade(ativo, cve) is None:
        print("Vulnerabilidade não encontrada para este ativo.")
        return False
    print("Deixe em branco para manter o valor atual.")
    descricao = ler_texto("Nova descrição: ", False)
    prioridade = escolher_item("Nova prioridade: ", SEVERIDADES, True)
    tratamento = ler_texto("Novo tratamento: ", False)
    status = escolher_item("Novo status: ", STATUS, True)
    verificacao = ler_texto("Nova verificação: ", False)
    if not any([descricao, prioridade, tratamento, status, verificacao]):
        print("Nenhum campo foi alterado.")
        return False
    try:
        atualizar_vulnerabilidade(ativos, identificador, cve, descricao, prioridade,
                                  tratamento, status, verificacao)
        print("Vulnerabilidade atualizada com sucesso.")
        return True
    except DadosInvalidosError as erro:
        print(erro)
        return False


def remover_vulnerabilidade_tela(ativos):
    print("\nRemoção de vulnerabilidade")
    identificador = ler_inteiro("ID do ativo afetado: ")
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        print("Ativo não encontrado.")
        return False
    cve = ler_cve("CVE da vulnerabilidade: ")
    vulnerabilidade = buscar_vulnerabilidade(ativo, cve)
    if vulnerabilidade is None:
        print("Vulnerabilidade não encontrada para este ativo.")
        return False
    print(f"Confirme o alvo: {vulnerabilidade.cve} - {vulnerabilidade.descricao}.")
    try:
        if excluir_vulnerabilidade(
                ativos, identificador, cve,
                ler_texto("Digite SIM para confirmar: ").upper() == "SIM"):
            print("Vulnerabilidade removida com sucesso.")
            return True
        print("Remoção cancelada.")
        return False
    except DadosInvalidosError as erro:
        print(erro)
        return False


def mostrar_resumo(ativos):
    total = sum(len(ativo.vulnerabilidades) for ativo in ativos.values())
    mostrar_linha()
    print(f"Total de ativos cadastrados: {len(ativos)}")
    print(f"Total de vulnerabilidades cadastradas: {total}")


def mostrar_menu():
    mostrar_linha()
    print("INVENTÁRIO DE ATIVOS E VULNERABILIDADES")
    print("1 - Cadastrar ativo\n2 - Listar ativos\n3 - Buscar ativo\n4 - Atualizar ativo")
    print("5 - Remover ativo\n6 - Cadastrar vulnerabilidade\n7 - Consultar vulnerabilidades")
    print("8 - Atualizar vulnerabilidade\n9 - Remover vulnerabilidade")
    print("10 - Mostrar resumo do inventário\n0 - Sair")


def executar_programa(ativos, caminho_dados):
    print(f"Base carregada: {len(ativos)} ativo(s).")
    while True:
        mostrar_menu()
        opcao = ler_texto("Escolha uma opção: ")
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
            salvar_ativos(ativos, caminho_dados)
            print("Programa encerrado.")
            break
        else:
            print("Opção inválida. Escolha uma opção do menu.")
        if alterou:
            salvar_ativos(ativos, caminho_dados)
