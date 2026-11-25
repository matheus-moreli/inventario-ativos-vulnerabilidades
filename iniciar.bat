@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Inventario de Ativos e Vulnerabilidades
cd /d "%~dp0" || exit /b 1
set "PYTHONUTF8=1"
set "STATUS=1"
set "VENV_PY=%~dp0.venv\Scripts\python.exe"

if /i "%~1"=="--ajuda" goto ajuda
if exist "%VENV_PY%" goto dependencias

echo [1/2] Criando ambiente virtual local...
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 (
    py -3 -m venv .venv
    if errorlevel 1 goto erro_ambiente
) else (
    python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
    if errorlevel 1 goto erro_python
    python -m venv .venv
    if errorlevel 1 goto erro_ambiente
)

:dependencias
"%VENV_PY%" -c "import rich, prompt_toolkit, pytest" >nul 2>&1
if errorlevel 1 (
    echo [2/2] Instalando dependencias da aplicacao e do Pytest...
    "%VENV_PY%" -m pip --version >nul 2>&1
    if errorlevel 1 (
        "%VENV_PY%" -m ensurepip --upgrade
        if errorlevel 1 goto erro_dependencias
    )
    "%VENV_PY%" -m pip install --disable-pip-version-check -r requirements.txt -r requirements-dev.txt
    if errorlevel 1 goto erro_dependencias
    "%VENV_PY%" -c "import rich, prompt_toolkit, pytest"
    if errorlevel 1 goto erro_dependencias
)

if /i "%~1"=="--instalar" goto pronto
if /i "%~1"=="--testes" goto testes

echo [OK] Iniciando o inventario...
"%VENV_PY%" app.py %*
set "STATUS=%ERRORLEVEL%"
if not "%STATUS%"=="0" echo [ERRO] O inventario terminou com codigo %STATUS%.
if "%~1"=="" pause
exit /b %STATUS%

:testes
"%VENV_PY%" app.py %*
exit /b %ERRORLEVEL%

:pronto
echo [OK] Aplicacao e Pytest disponiveis no ambiente local.
exit /b 0

:ajuda
echo iniciar.bat             Abre o inventario
echo iniciar.bat --testes    Executa a suite Pytest
echo iniciar.bat --instalar  Prepara o ambiente sem abrir o programa
exit /b 0

:erro_python
echo [ERRO] Python 3.10 ou superior nao encontrado.
goto falha

:erro_ambiente
echo [ERRO] Nao foi possivel criar o ambiente .venv na pasta do projeto.
goto falha

:erro_dependencias
echo [ERRO] Falha ao instalar as dependencias. Confira a internet e a saida acima.

:falha
if "%~1"=="" pause
exit /b 1
