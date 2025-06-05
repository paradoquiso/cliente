# -*- coding: utf-8 -*-
import sys
import os
import sqlite3
import time # Importar time para verificar expiração do token
from datetime import datetime, timezone
import io
import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import pandas as pd
import json
from werkzeug.security import generate_password_hash, check_password_hash
from src.utils import formatar_data_brasileira
# Importar as funções do novo módulo de autenticação ML
from src.mercado_livre import (
    get_authorization_url,
    exchange_code_for_token,
    refresh_access_token,
    buscar_produto_por_ean as buscar_produto_online, # Renomeado para clareza
    fallback_busca_produto # Pode ser útil
)
import re # Importar re para limpar nome de arquivo
import logging # Adicionar logging

# Configurar logging básico
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Chave secreta para a sessão Flask (essencial para segurança)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ean_app_secret_key_default_dev_only_unsafe") 

# Configuração do banco de dados SQLite (mantida)
DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "produtos.db")
logger.info(f"Usando banco de dados SQLite em: {DATABASE_PATH}")

# --- Funções de Banco de Dados (mantidas) ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row 
    return conn

def init_database():
    # ... (código de inicialização do DB mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = ON;")
            # Criar tabela usuarios se não existir
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                senha_hash TEXT NOT NULL,
                admin INTEGER DEFAULT 0
            );
            """)
            # Criar tabela responsaveis se não existir
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS responsaveis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                pin TEXT NOT NULL
            );
            """)
            # Criar tabela produtos se não existir
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS produtos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ean TEXT NOT NULL,
                nome TEXT NOT NULL,
                cor TEXT,
                voltagem TEXT,
                modelo TEXT,
                quantidade INTEGER NOT NULL,
                usuario_id INTEGER NOT NULL,
                timestamp TEXT,
                enviado INTEGER DEFAULT 0,
                data_envio TEXT,
                validado INTEGER DEFAULT 0,
                validador_id INTEGER,
                data_validacao TEXT,
                responsavel_id INTEGER,
                responsavel_pin TEXT,
                preco_medio REAL, 
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id),
                FOREIGN KEY (validador_id) REFERENCES usuarios (id),
                FOREIGN KEY (responsavel_id) REFERENCES responsaveis (id)
            );
            """)
            
            # Verificar e adicionar colunas ausentes na tabela produtos (migração)
            cursor.execute("PRAGMA table_info(produtos)")
            columns = [column[1] for column in cursor.fetchall()]
            if "responsavel_id" not in columns:
                logger.info("Adicionando coluna 'responsavel_id' à tabela produtos...")
                cursor.execute("ALTER TABLE produtos ADD COLUMN responsavel_id INTEGER REFERENCES responsaveis(id)")
            if "responsavel_pin" not in columns:
                logger.info("Adicionando coluna 'responsavel_pin' à tabela produtos...")
                cursor.execute("ALTER TABLE produtos ADD COLUMN responsavel_pin TEXT")
            if "preco_medio" not in columns:
                logger.info("Adicionando coluna 'preco_medio' à tabela produtos...")
                cursor.execute("ALTER TABLE produtos ADD COLUMN preco_medio REAL")

            # Verificar e inserir usuário admin padrão se não existir
            cursor.execute("SELECT COUNT(*) FROM usuarios WHERE nome = ?", ("admin",))
            admin_exists = cursor.fetchone()[0]
            if admin_exists == 0:
                admin_hash = generate_password_hash("admin")
                cursor.execute("INSERT INTO usuarios (nome, senha_hash, admin) VALUES (?, ?, ?)", 
                              ("admin", admin_hash, 1))
                logger.info("Usuário admin padrão criado.")

            # Inicializar responsáveis se a tabela estiver vazia
            inicializar_responsaveis(conn)
            conn.commit()
            logger.info("Banco de dados SQLite inicializado/verificado com sucesso.")
    except sqlite3.Error as e:
        logger.error(f"Erro CRÍTICO ao inicializar o banco de dados SQLite: {e}", exc_info=True)

def inicializar_responsaveis(conn):
    # ... (código mantido igual ao original) ...
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM responsaveis")
        count = cursor.fetchone()[0]
        if count == 0:
            responsaveis = [
                ("Liliane", "5584"), ("Rogerio", "9841"),
                ("Celso", "2122"), ("Marcos", "6231")
            ]
            cursor.executemany("INSERT INTO responsaveis (nome, pin) VALUES (?, ?)", responsaveis)
            logger.info(f"Responsáveis inicializados: {len(responsaveis)}")
    except sqlite3.Error as e:
        logger.error(f"Erro ao inicializar responsáveis: {e}")

# --- Forçar inicialização do DB ao iniciar a aplicação --- 
init_database()
# --------------------------------------------------------

# Registrar filtro Jinja2 (mantido)
@app.template_filter("data_brasileira")
def data_brasileira_filter(data):
    # ... (código mantido igual ao original) ...
    if isinstance(data, str):
        try:
            data = datetime.fromisoformat(data.replace("Z", "+00:00"))
        except ValueError:
            try:
                 data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                 try:
                     data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
                 except ValueError:
                     return data
    return formatar_data_brasileira(data)

# --- Funções de Responsáveis e Usuários (mantidas) ---
def obter_responsaveis():
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, nome FROM responsaveis ORDER BY nome")
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Erro ao obter responsáveis: {e}")
        return []

def verificar_pin_responsavel(responsavel_id, pin):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT pin FROM responsaveis WHERE id = ?", (responsavel_id,))
            resultado = cursor.fetchone()
            return bool(resultado and resultado["pin"] == pin)
    except sqlite3.Error as e:
        logger.error(f"Erro ao verificar PIN do responsável: {e}")
        return False

def obter_nome_responsavel(responsavel_id):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT nome FROM responsaveis WHERE id = ?", (responsavel_id,))
            resultado = cursor.fetchone()
            return resultado["nome"] if resultado else None
    except sqlite3.Error as e:
        logger.error(f"Erro ao obter nome do responsável: {e}")
        return None

def registrar_usuario(nome, senha):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            senha_hash = generate_password_hash(senha)
            cursor.execute("INSERT INTO usuarios (nome, senha_hash) VALUES (?, ?)", (nome, senha_hash))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"Tentativa de registrar usuário existente: {nome}")
        return False
    except sqlite3.Error as e:
        logger.error(f"Erro ao registrar usuário: {e}")
        return False

def verificar_usuario(nome, senha):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM usuarios WHERE nome = ?", (nome,))
            usuario = cursor.fetchone()
        if usuario and check_password_hash(usuario["senha_hash"], senha):
            return dict(usuario)
        return None
    except sqlite3.Error as e:
        logger.error(f"Erro ao verificar usuário: {e}")
        return None

def obter_nome_usuario(usuario_id):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT nome FROM usuarios WHERE id = ?", (usuario_id,))
            usuario = cursor.fetchone()
        return usuario["nome"] if usuario else None
    except sqlite3.Error as e:
        logger.error(f"Erro ao obter nome do usuário: {e}")
        return None

# --- Funções de Produtos (mantidas, exceto salvar_produto que usa preco_medio) ---
def carregar_produtos_usuario(usuario_id, apenas_nao_enviados=False):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            sql = "SELECT * FROM produtos WHERE usuario_id = ?" + (" AND enviado = 0" if apenas_nao_enviados else "") + " ORDER BY timestamp DESC"
            cursor.execute(sql, (usuario_id,))
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Erro ao carregar produtos do usuário: {e}")
        return []

def carregar_todas_listas_enviadas():
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT p.*, u.nome as nome_usuario, v.nome as nome_validador, r.nome as nome_responsavel
            FROM produtos p JOIN usuarios u ON p.usuario_id = u.id 
            LEFT JOIN usuarios v ON p.validador_id = v.id
            LEFT JOIN responsaveis r ON p.responsavel_id = r.id
            WHERE p.enviado = 1 ORDER BY p.data_envio DESC
            """)
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Erro ao carregar todas as listas enviadas: {e}")
        return []

def pesquisar_produtos(termo_pesquisa):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            termo_like = f"%{termo_pesquisa}%"
            cursor.execute("""
            SELECT p.*, u.nome as nome_usuario, v.nome as nome_validador, r.nome as nome_responsavel
            FROM produtos p JOIN usuarios u ON p.usuario_id = u.id 
            LEFT JOIN usuarios v ON p.validador_id = v.id
            LEFT JOIN responsaveis r ON p.responsavel_id = r.id
            WHERE p.enviado = 1 AND (LOWER(p.ean) LIKE LOWER(?) OR LOWER(p.nome) LIKE LOWER(?) OR LOWER(p.cor) LIKE LOWER(?) OR LOWER(p.modelo) LIKE LOWER(?))
            ORDER BY p.data_envio DESC
            """, (termo_like, termo_like, termo_like, termo_like))
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Erro ao pesquisar produtos: {e}")
        return []

def buscar_produto_local(ean, usuario_id):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM produtos WHERE ean = ? AND usuario_id = ? AND enviado = 0", (ean, usuario_id))
            produto = cursor.fetchone()
        return dict(produto) if produto else None
    except sqlite3.Error as e:
        logger.error(f"Erro ao buscar produto local: {e}")
        return None

def salvar_produto(produto, usuario_id):
    # ... (código mantido igual ao original, já incluía preco_medio) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, quantidade FROM produtos WHERE ean = ? AND usuario_id = ? AND enviado = 0", (produto['ean'], usuario_id))
            existing = cursor.fetchone()
            timestamp_obj = produto.get("timestamp")
            timestamp_str = (timestamp_obj.astimezone(timezone.utc).isoformat() 
                             if isinstance(timestamp_obj, datetime) 
                             else datetime.now(timezone.utc).isoformat())
            preco_medio = produto.get("preco_medio") # Já estava aqui

            if existing:
                nova_quantidade = existing["quantidade"] + produto["quantidade"]
                cursor.execute("UPDATE produtos SET quantidade = ?, timestamp = ?, preco_medio = ? WHERE id = ?",
                               (nova_quantidade, timestamp_str, preco_medio, existing["id"]))
            else:
                cursor.execute("INSERT INTO produtos (ean, nome, cor, voltagem, modelo, quantidade, usuario_id, timestamp, enviado, preco_medio) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                               (produto['ean'], produto["nome"], produto.get("cor"), produto.get("voltagem"), produto.get("modelo"), produto["quantidade"], usuario_id, timestamp_str, preco_medio))
            conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"Erro ao salvar produto: {e}")
        return False
    except Exception as e:
        logger.error(f"Erro inesperado ao salvar produto: {e}", exc_info=True)
        return False

def enviar_lista_produtos(usuario_id, responsavel_id, pin):
    # ... (código mantido igual ao original) ...
    try:
        if not verificar_pin_responsavel(responsavel_id, pin):
            logger.warning(f"PIN inválido para o responsável ID {responsavel_id} ao tentar enviar lista.")
            return None # Retorna None para indicar falha de PIN
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            data_envio_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE produtos SET enviado = 1, data_envio = ?, responsavel_id = ?, responsavel_pin = ? WHERE usuario_id = ? AND enviado = 0",
                           (data_envio_str, responsavel_id, pin, usuario_id))
            affected_rows = cursor.rowcount
            conn.commit()
            logger.info(f"Produtos marcados como enviados para usuário {usuario_id}: {affected_rows}")
            return data_envio_str # Retorna a string da data de envio
    except sqlite3.Error as e:
        logger.error(f"Erro ao enviar lista de produtos: {e}")
        return "erro_db"
    except Exception as e:
        logger.error(f"Erro inesperado ao enviar lista: {e}", exc_info=True)
        return "erro_inesperado"

def deletar_produto(produto_id, usuario_id):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM produtos WHERE id = ? AND usuario_id = ? AND enviado = 0", (produto_id, usuario_id))
            conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"Erro ao deletar produto: {e}")
        return False

def validar_produto(produto_id, validador_id):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            data_validacao_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE produtos SET validado = 1, validador_id = ?, data_validacao = ? WHERE id = ? AND enviado = 1",
                           (validador_id, data_validacao_str, produto_id))
            conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"Erro ao validar produto: {e}")
        return False

def desvalidar_produto(produto_id):
    # ... (código mantido igual ao original) ...
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE produtos SET validado = 0, validador_id = NULL, data_validacao = NULL WHERE id = ? AND enviado = 1",
                           (produto_id,))
            conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"Erro ao desvalidar produto: {e}")
        return False

# --- Funções Auxiliares para Autenticação ML ---
def get_valid_ml_token():
    """Verifica se há um token ML válido na sessão e tenta renová-lo se expirado."""
    ml_token_info = session.get("ml_token")
    if not ml_token_info:
        logger.info("Nenhum token ML encontrado na sessão.")
        return None

    current_time = time.time()
    # Verificar se o token expirou (com uma margem de 60 segundos)
    if current_time >= ml_token_info.get("expires_at", 0) - 60:
        logger.info("Token ML expirado ou prestes a expirar. Tentando renovar...")
        refresh_token = ml_token_info.get("refresh_token")
        if not refresh_token:
            logger.warning("Refresh token não encontrado na sessão. Não é possível renovar.")
            session.pop("ml_token", None) # Limpa token inválido
            return None
        
        new_token_info = refresh_access_token(refresh_token)
        if new_token_info:
            logger.info("Token ML renovado com sucesso.")
            session["ml_token"] = new_token_info # Atualiza a sessão
            return new_token_info.get("access_token")
        else:
            logger.error("Falha ao renovar o token ML. Requer nova autorização.")
            session.pop("ml_token", None) # Limpa token inválido
            return None
    else:
        # Token ainda válido
        logger.debug("Token ML válido encontrado na sessão.")
        return ml_token_info.get("access_token")

# --- Rotas Flask ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form["nome"]
        senha = request.form["senha"]
        usuario = verificar_usuario(nome, senha)
        if usuario:
            session["usuario_id"] = usuario['id']
            session['usuario_nome'] = usuario["nome"]
            session["is_admin"] = bool(usuario["admin"])
            flash("Login realizado com sucesso!", "success")
            logger.info(f"Usuário {nome} (ID: {usuario['id']}) logado com sucesso.")
            return redirect(url_for("index"))
        else:
            flash("Nome de usuário ou senha inválidos.", "danger")
            logger.warning(f"Tentativa de login falhou para o usuário: {nome}")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nome = request.form["nome"]
        senha = request.form["senha"]
        if registrar_usuario(nome, senha):
            flash("Usuário registrado com sucesso! Faça o login.", "success")
            logger.info(f"Novo usuário registrado: {nome}")
            return redirect(url_for("login"))
        else:
            flash("Nome de usuário já existe.", "danger")
    return render_template("register.html")

@app.route("/logout")
def logout():
    usuario_nome = session.get("usuario_nome", "Desconhecido")
    session.pop("usuario_id", None)
    session.pop("usuario_nome", None)
    session.pop("is_admin", None)
    session.pop("ml_token", None) # Limpa token ML ao deslogar
    flash("Você foi desconectado.", "info")
    logger.info(f"Usuário {usuario_nome} deslogado.")
    return redirect(url_for("login"))

# --- Rotas de Autenticação Mercado Livre ---

@app.route("/ml_login")
def ml_login():
    if "usuario_id" not in session:
        flash("Faça login na aplicação primeiro.", "warning")
        return redirect(url_for("login"))

    auth_url = get_authorization_url()
    if auth_url:
        logger.info(f"Redirecionando usuário {session['usuario_nome']} para autorização ML.")
        return redirect(auth_url)
    else:
        flash("Erro ao gerar URL de autorização do Mercado Livre. Verifique as configurações (variáveis de ambiente).", "danger")
        logger.error("Falha ao gerar URL de autorização ML. Variáveis de ambiente ausentes?")
        return redirect(url_for("index"))

@app.route("/ml_callback")
def ml_callback():
    if "usuario_id" not in session:
        flash("Sessão inválida. Faça login novamente.", "warning")
        return redirect(url_for("login"))

    code = request.args.get("code")
    error = request.args.get("error")
    error_description = request.args.get("error_description")

    if error:
        flash(f"Erro na autorização do Mercado Livre: {error_description or error}", "danger")
        logger.error(f"Erro retornado pelo callback ML: {error} - {error_description}")
        return redirect(url_for("index"))

    if not code:
        flash("Código de autorização não recebido do Mercado Livre.", "danger")
        logger.error("Callback ML chamado sem código de autorização.")
        return redirect(url_for("index"))

    # Trocar o código pelo token
    token_info = exchange_code_for_token(code)
    if token_info:
        session["ml_token"] = token_info # Armazena todo o dict do token na sessão
        flash("Aplicação autorizada com sucesso no Mercado Livre!", "success")
        logger.info(f"Token ML obtido e armazenado na sessão para o usuário {session['usuario_nome']}.")
    else:
        flash("Falha ao obter o token de acesso do Mercado Livre após autorização.", "danger")
        logger.error("Falha ao trocar código por token após callback ML.")

    return redirect(url_for("index"))

# --- Rota Principal e de Produtos ---

@app.route("/")
def index():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    usuario_id = session["usuario_id"]
    produtos = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
    responsaveis = obter_responsaveis()
    
    # Verifica se o token ML existe e é válido (sem tentar renovar aqui, apenas para UI)
    ml_token_valido = bool(session.get("ml_token") and time.time() < session["ml_token"].get("expires_at", 0) - 60)
    
    return render_template("index.html", 
                           produtos=produtos, 
                           responsaveis=responsaveis,
                           ml_token_valido=ml_token_valido) # Passa o status do token para o template

@app.route("/buscar_ean", methods=["POST"])
def buscar_ean_route():
    if "usuario_id" not in session:
        return jsonify({"success": False, "message": "Usuário não logado.", "needs_login": True}), 401

    ean = request.form.get("ean")
    if not ean:
        return jsonify({"success": False, "message": "Código EAN não fornecido."}), 400

    # Tenta obter um token ML válido (renova se necessário)
    access_token = get_valid_ml_token()
    
    if not access_token:
        logger.info(f"Busca EAN {ean} falhou: Token ML inválido ou ausente. Requer autorização.")
        return jsonify({"success": False, "message": "Autorização do Mercado Livre necessária.", "needs_ml_auth": True}), 401

    # Realiza a busca online usando o token obtido
    logger.info(f"Realizando busca online para EAN {ean} com token válido.")
    resultado_busca = buscar_produto_online(ean, access_token)

    # Se a busca retornar erro de token inválido, limpar sessão e pedir re-autenticação
    if not resultado_busca.get("success") and resultado_busca.get("error") == "invalid_token":
        logger.warning(f"Busca EAN {ean} falhou com erro de token inválido (401). Limpando token da sessão.")
        session.pop("ml_token", None)
        return jsonify({"success": False, "message": "Sessão com Mercado Livre expirou. Autorize novamente.", "needs_ml_auth": True}), 401

    return jsonify(resultado_busca)

@app.route("/adicionar_produto", methods=["POST"])
def adicionar_produto():
    if "usuario_id" not in session:
        flash("Faça login para adicionar produtos.", "warning")
        return redirect(url_for("login"))

    try:
        produto = {
            "ean": request.form["ean"],
            "nome": request.form["nome"],
            "cor": request.form.get("cor"),
            "voltagem": request.form.get("voltagem"),
            "modelo": request.form.get("modelo"),
            "quantidade": int(request.form["quantidade"]),
            "preco_medio": float(request.form["preco_medio"]) if request.form.get("preco_medio") else None, # Adicionado
            "timestamp": datetime.now(timezone.utc) # Adiciona timestamp na criação
        }
        if salvar_produto(produto, session["usuario_id"]):
            flash("Produto adicionado com sucesso!", "success")
            logger.info(f"Produto EAN {produto['ean']} adicionado/atualizado por usuário {session['usuario_nome']}.")
        else:
            flash("Erro ao salvar o produto.", "danger")
            logger.error(f"Falha ao salvar produto EAN {produto['ean']} por usuário {session['usuario_nome']}.")
    except ValueError:
        flash("Quantidade inválida.", "danger")
    except Exception as e:
        flash(f"Erro inesperado: {str(e)}", "danger")
        logger.error(f"Erro inesperado ao adicionar produto: {e}", exc_info=True)
        
    return redirect(url_for("index"))

@app.route("/deletar_produto/<int:produto_id>", methods=["POST"])
def deletar_produto_route(produto_id):
    if "usuario_id" not in session:
        flash("Faça login para deletar produtos.", "warning")
        return redirect(url_for("login"))

    if deletar_produto(produto_id, session["usuario_id"]):
        flash("Produto deletado com sucesso!", "success")
        logger.info(f"Produto ID {produto_id} deletado por usuário {session['usuario_nome']}.")
    else:
        flash("Erro ao deletar o produto.", "danger")
        logger.error(f"Falha ao deletar produto ID {produto_id} por usuário {session['usuario_nome']}.")
    return redirect(url_for("index"))

@app.route("/enviar_lista", methods=["POST"])
def enviar_lista():
    if "usuario_id" not in session:
        flash("Faça login para enviar a lista.", "warning")
        return redirect(url_for("login"))

    responsavel_id = request.form.get("responsavel_id")
    pin = request.form.get("pin")

    if not responsavel_id or not pin:
        flash("Selecione o responsável e digite o PIN.", "warning")
        return redirect(url_for("index"))

    resultado_envio = enviar_lista_produtos(session["usuario_id"], responsavel_id, pin)

    if resultado_envio and resultado_envio not in ["erro_db", "erro_inesperado"]:
        flash(f"Lista enviada com sucesso em {data_brasileira_filter(resultado_envio)}!", "success")
        logger.info(f"Lista enviada por usuário {session['usuario_nome']} para responsável ID {responsavel_id}.")
    elif resultado_envio is None:
         flash("PIN inválido para o responsável selecionado.", "danger")
         logger.warning(f"Tentativa de envio de lista falhou (PIN inválido) por usuário {session['usuario_nome']} para responsável ID {responsavel_id}.")
    else:
        flash("Erro ao enviar a lista.", "danger")
        logger.error(f"Erro ao enviar lista por usuário {session['usuario_nome']}. Resultado: {resultado_envio}")
        
    return redirect(url_for("index"))

# --- Rotas de Admin ---
@app.route("/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        flash("Acesso não autorizado.", "danger")
        return redirect(url_for("index"))
    
    termo_pesquisa = request.args.get("q", "")
    if termo_pesquisa:
        listas_enviadas = pesquisar_produtos(termo_pesquisa)
    else:
        listas_enviadas = carregar_todas_listas_enviadas()
        
    return render_template("admin.html", listas=listas_enviadas, termo_pesquisa=termo_pesquisa)

@app.route("/admin/validar/<int:produto_id>", methods=["POST"])
def validar_produto_route(produto_id):
    if not session.get("is_admin"):
        return jsonify({"success": False, "message": "Acesso não autorizado."}), 403

    if validar_produto(produto_id, session["usuario_id"]):
        logger.info(f"Produto ID {produto_id} validado por admin {session['usuario_nome']}.")
        return jsonify({"success": True, "message": "Produto validado.", "validador": session['usuario_nome'], "data_validacao": formatar_data_brasileira(datetime.now(timezone.utc))})
    else:
        logger.error(f"Falha ao validar produto ID {produto_id} por admin {session['usuario_nome']}.")
        return jsonify({"success": False, "message": "Erro ao validar produto."}), 500

@app.route("/admin/desvalidar/<int:produto_id>", methods=["POST"])
def desvalidar_produto_route(produto_id):
    if not session.get("is_admin"):
        return jsonify({"success": False, "message": "Acesso não autorizado."}), 403

    if desvalidar_produto(produto_id):
        logger.info(f"Produto ID {produto_id} desvalidado por admin {session['usuario_nome']}.")
        return jsonify({"success": True, "message": "Validação removida."})
    else:
        logger.error(f"Falha ao desvalidar produto ID {produto_id} por admin {session['usuario_nome']}.")
        return jsonify({"success": False, "message": "Erro ao remover validação."}), 500

@app.route("/admin/exportar")
def exportar_excel():
    if not session.get("is_admin"):
        flash("Acesso não autorizado.", "danger")
        return redirect(url_for("index"))

    try:
        listas_enviadas = carregar_todas_listas_enviadas()
        if not listas_enviadas:
            flash("Nenhuma lista enviada para exportar.", "warning")
            return redirect(url_for("admin_dashboard"))

        # Converter para DataFrame do Pandas
        df = pd.DataFrame(listas_enviadas)
        
        # Selecionar e renomear colunas
        df = df[["ean", "nome", "cor", "voltagem", "modelo", "quantidade", "preco_medio", "nome_usuario", "timestamp", "data_envio", "nome_responsavel", "validado", "nome_validador", "data_validacao"]]
        df.rename(columns={
            "ean": "EAN", "nome": "Nome do Produto", "cor": "Cor", "voltagem": "Voltagem", "modelo": "Modelo",
            "quantidade": "Quantidade", "preco_medio": "Preço Médio (ML)", "nome_usuario": "Usuário Cadastro", "timestamp": "Data Cadastro",
            "data_envio": "Data Envio", "nome_responsavel": "Responsável Envio", "validado": "Validado",
            "nome_validador": "Usuário Validação", "data_validacao": "Data Validação"
        }, inplace=True)

        # Formatar colunas de data
        for col in ["Data Cadastro", "Data Envio", "Data Validação"]:
            if col in df.columns:
                 # Tenta converter para datetime e depois formatar, tratando erros
                 df[col] = pd.to_datetime(df[col], errors='coerce').dt.strftime("%d/%m/%Y %H:%M:%S")
                 df[col] = df[col].fillna("") # Substitui NaT por string vazia
        
        # Formatar coluna Validado
        if "Validado" in df.columns:
            df["Validado"] = df["Validado"].apply(lambda x: "Sim" if x == 1 else "Não")
            
        # Formatar Preço Médio
        if "Preço Médio (ML)" in df.columns:
            df["Preço Médio (ML)"] = df["Preço Médio (ML)"].apply(lambda x: f"R$ {x:.2f}".replace(".", ",") if pd.notnull(x) else "")

        # Criar arquivo Excel em memória
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Produtos Enviados')
            # Opcional: ajustar largura das colunas
            workbook = writer.book
            worksheet = writer.sheets["Produtos Enviados"]
            for i, col in enumerate(df.columns):
                 column_len = max(df[col].astype(str).map(len).max(), len(col))
                 worksheet.set_column(i, i, column_len + 2) 

        output.seek(0)

        # Gerar nome do arquivo
        timestamp_atual = datetime.now().strftime("%Y%m%d_%H%M%S")
        nome_arquivo = f"export_produtos_enviados_{timestamp_atual}.xlsx"
        
        logger.info(f"Exportação Excel gerada por admin {session['usuario_nome']}.")
        return send_file(output, download_name=nome_arquivo, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

    except Exception as e:
        flash(f"Erro ao gerar o arquivo Excel: {str(e)}", "danger")
        logger.error(f"Erro ao exportar Excel: {e}", exc_info=True)
        return redirect(url_for("admin_dashboard"))

# --- Execução Principal ---
if __name__ == "__main__":
    # Usar variáveis de ambiente para host e porta, se disponíveis
    host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000)) # Render usa PORT
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    
    logger.info(f"Iniciando Flask app em {host}:{port} (Debug: {debug_mode})")
    # Importante: Não usar debug=True em produção!
    app.run(host=host, port=port, debug=debug_mode)
