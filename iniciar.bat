@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Inventario de Ativos e Vulnerabilidades

rem Executa sempre a partir da pasta deste arquivo, mesmo com duplo clique.
cd /d "%~dp0"
if errorlevel 1 goto erro_pasta

rem Use o launcher oficial do Windows, se existir; caso contrario, use python.
set "PYTHON="
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys; assert sys.version_info >= (3, 9)" >nul 2>nul
    if not errorlevel 1 set "PYTHON=py -3"
)
if not defined PYTHON (
    where python >nul 2>nul
    if not errorlevel 1 (
        python -c "import sys; assert sys.version_info >= (3, 9)" >nul 2>nul
        if not errorlevel 1 set "PYTHON=python"
    )
)
if not defined PYTHON goto erro_python

echo.
echo ================================================
echo   INVENTARIO DE ATIVOS E VULNERABILIDADES
echo ================================================
echo.

rem Confere os dois pacotes utilizados pela interface de terminal.
%PYTHON% -c "import rich, prompt_toolkit" >nul 2>nul
if errorlevel 1 (
    echo [INFO] Preparando dependencias do projeto...
    echo [INFO] Internet pode ser necessaria na primeira execucao.
    %PYTHON% -m pip install --disable-pip-version-check --no-cache-dir -r "requirements.txt"
    if errorlevel 1 goto erro_dependencias
    %PYTHON% -c "import rich, prompt_toolkit" >nul 2>nul
    if errorlevel 1 goto erro_dependencias
)

echo [OK] Python e dependencias disponiveis.
echo [INFO] Iniciando o aplicativo...
echo.
%PYTHON% app.py %*
set "STATUS=%ERRORLEVEL%"
if not "%STATUS%"=="0" echo [ERRO] O aplicativo terminou com codigo %STATUS%.

rem Modo de testes automatizado nao pode aguardar teclado no CI.
if /i "%~1"=="--testes" exit /b %STATUS%

echo.
echo [INFO] Aplicativo encerrado. Pressione uma tecla para fechar.
pause >nul
exit /b %STATUS%

:erro_python
echo [ERRO] Python 3.9 ou superior nao encontrado.
echo Instale Python 3 em um ambiente autorizado ou procure o suporte de TI.
goto falha

:erro_pasta
echo [ERRO] Nao foi possivel acessar a pasta do projeto.
goto falha

:erro_dependencias
echo [ERRO] Falha ao instalar ou carregar as dependencias.
echo Se nao houver acesso a internet ou espaco, fale com o suporte de TI.
echo Alternativa manual: py -m pip install -r requirements.txt
goto falha

:falha
if /i "%~1"=="--testes" exit /b 1
echo.
pause
exit /b 1
