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
# Importar as funções do módulo de integração ML atualizado
from src.mercado_livre import (
    get_authorization_url,
    exchange_code_for_token,
    buscar_produto_por_ean as buscar_produto_online, # Renomeado para clareza
    fallback_busca_produto,
    load_token_data, # Para verificar se o token existe
    TOKEN_FILE_PATH # Para verificar se o arquivo existe
)
import re # Importar re para limpar nome de arquivo
import logging # Adicionar logging

# Configurar logging básico
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Chave secreta para a sessão Flask (essencial para segurança)
# IMPORTANTE: Mudar para uma variável de ambiente segura em produção!
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ean_app_secret_key_default_dev_only_unsafe") 

# Configuração do banco de dados SQLite (mantida)
DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "produtos.db")
logger.info(f"Usando banco de dados SQLite em: {DATABASE_PATH}")

# --- Funções de Banco de Dados (mantidas como no original) ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row 
    return conn

def init_database():
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
        # Em um app real, talvez parar a aplicação aqui?

def inicializar_responsaveis(conn):
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
    if isinstance(data, str):
        try:
            # Tenta converter de ISO format com ou sem Z
            data = datetime.fromisoformat(data.replace("Z", "+00:00"))
        except ValueError:
            # Tenta formatos comuns se ISO falhar
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    data = datetime.strptime(data, fmt)
                    break # Sai do loop se a conversão for bem-sucedida
                except ValueError:
                    pass # Tenta o próximo formato
            else: # Se nenhum formato funcionou
                return data # Retorna a string original
    # Se for um objeto datetime, formata
    if isinstance(data, datetime):
         return formatar_data_brasileira(data)
    return data # Retorna como está se não for string nem datetime

# --- Funções de Responsáveis e Usuários (mantidas como no original) ---
def obter_responsaveis():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, nome FROM responsaveis ORDER BY nome")
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Erro ao obter responsáveis: {e}")
        return []

def verificar_pin_responsavel(responsavel_id, pin):
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
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT nome FROM usuarios WHERE id = ?", (usuario_id,))
            usuario = cursor.fetchone()
        return usuario["nome"] if usuario else None
    except sqlite3.Error as e:
        logger.error(f"Erro ao obter nome do usuário: {e}")
        return None

# --- Funções de Produtos (mantidas, salvar_produto usa preco_medio) ---
def carregar_produtos_usuario(usuario_id, apenas_nao_enviados=False):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            sql = "SELECT * FROM produtos WHERE usuario_id = ?" + (" AND enviado = 0" if apenas_nao_enviados else "") + " ORDER BY timestamp DESC"
            cursor.execute(sql, (usuario_id,))
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Erro ao carregar produtos do usuário {usuario_id}: {e}")
        return []

def carregar_todas_listas_enviadas():
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
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM produtos WHERE ean = ? AND usuario_id = ? AND enviado = 0", (ean, usuario_id))
            produto = cursor.fetchone()
        return dict(produto) if produto else None
    except sqlite3.Error as e:
        logger.error(f"Erro ao buscar produto local para EAN {ean}, usuário {usuario_id}: {e}")
        return None

def salvar_produto(produto, usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, quantidade FROM produtos WHERE ean = ? AND usuario_id = ? AND enviado = 0", (produto['ean'], usuario_id))
            existing = cursor.fetchone()
            
            # Garante que o timestamp seja sempre um objeto datetime antes de formatar
            timestamp_obj = produto.get("timestamp")
            if not isinstance(timestamp_obj, datetime):
                 timestamp_obj = datetime.now(timezone.utc)
            timestamp_str = timestamp_obj.isoformat()

            preco_medio = produto.get("preco_medio")

            if existing:
                nova_quantidade = existing["quantidade"] + produto["quantidade"]
                logger.info(f"Atualizando produto existente (ID: {existing['id']}) EAN: {produto['ean']} para usuário {usuario_id}. Nova quantidade: {nova_quantidade}")
                cursor.execute("UPDATE produtos SET quantidade = ?, timestamp = ?, preco_medio = ? WHERE id = ?",
                               (nova_quantidade, timestamp_str, preco_medio, existing["id"]))
            else:
                logger.info(f"Inserindo novo produto EAN: {produto['ean']} para usuário {usuario_id}.")
                cursor.execute("INSERT INTO produtos (ean, nome, cor, voltagem, modelo, quantidade, usuario_id, timestamp, enviado, preco_medio) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                               (produto['ean'], produto["nome"], produto.get("cor"), produto.get("voltagem"), produto.get("modelo"), produto["quantidade"], usuario_id, timestamp_str, preco_medio))
            conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"Erro de banco de dados ao salvar produto EAN {produto.get('ean')} para usuário {usuario_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Erro inesperado ao salvar produto EAN {produto.get('ean')} para usuário {usuario_id}: {e}", exc_info=True)
        return False

def enviar_lista_produtos(usuario_id, responsavel_id, pin):
    try:
        if not verificar_pin_responsavel(responsavel_id, pin):
            logger.warning(f"PIN inválido para o responsável ID {responsavel_id} ao tentar enviar lista do usuário {usuario_id}.")
            return None # PIN inválido
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            data_envio_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE produtos SET enviado = 1, data_envio = ?, responsavel_id = ?, responsavel_pin = ? WHERE usuario_id = ? AND enviado = 0",
                           (data_envio_str, responsavel_id, pin, usuario_id))
            affected_rows = cursor.rowcount
            if affected_rows == 0:
                 logger.warning(f"Nenhum produto não enviado encontrado para o usuário {usuario_id} ao tentar enviar.")
                 return "nenhum_produto" # Indica que não havia produtos para enviar
            conn.commit()
            logger.info(f"Produtos marcados como enviados para usuário {usuario_id}: {affected_rows}. Responsável: {responsavel_id}")
            return data_envio_str # Sucesso, retorna data de envio
    except sqlite3.Error as e:
        logger.error(f"Erro de banco de dados ao enviar lista de produtos do usuário {usuario_id}: {e}")
        return "erro_db"
    except Exception as e:
        logger.error(f"Erro inesperado ao enviar lista do usuário {usuario_id}: {e}", exc_info=True)
        return "erro_inesperado"

def deletar_produto(produto_id, usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Garante que só pode deletar produtos não enviados do próprio usuário
            cursor.execute("DELETE FROM produtos WHERE id = ? AND usuario_id = ? AND enviado = 0", (produto_id, usuario_id))
            affected_rows = cursor.rowcount
            conn.commit()
            if affected_rows > 0:
                logger.info(f"Produto ID {produto_id} deletado com sucesso pelo usuário {usuario_id}.")
                return True
            else:
                logger.warning(f"Tentativa de deletar produto ID {produto_id} falhou (não encontrado, já enviado ou pertence a outro usuário). Usuário: {usuario_id}")
                return False
    except sqlite3.Error as e:
        logger.error(f"Erro de banco de dados ao deletar produto ID {produto_id} pelo usuário {usuario_id}: {e}")
        return False

def validar_lista(data_envio, validador_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            data_validacao_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE produtos SET validado = 1, validador_id = ?, data_validacao = ? WHERE data_envio = ? AND enviado = 1",
                           (validador_id, data_validacao_str, data_envio))
            affected_rows = cursor.rowcount
            conn.commit()
            if affected_rows > 0:
                logger.info(f"Lista enviada em {data_envio} validada por usuário {validador_id}. {affected_rows} produtos atualizados.")
                return True
            else:
                 logger.warning(f"Nenhum produto encontrado para validar com data de envio {data_envio}.")
                 return False # Nenhum produto encontrado com essa data de envio
    except sqlite3.Error as e:
        logger.error(f"Erro de banco de dados ao validar lista enviada em {data_envio} por usuário {validador_id}: {e}")
        return False

def obter_produtos_por_data_envio(data_envio):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT p.*, u.nome as nome_usuario, v.nome as nome_validador, r.nome as nome_responsavel
                FROM produtos p JOIN usuarios u ON p.usuario_id = u.id 
                LEFT JOIN usuarios v ON p.validador_id = v.id
                LEFT JOIN responsaveis r ON p.responsavel_id = r.id
                WHERE p.data_envio = ? AND p.enviado = 1
                ORDER BY p.nome
            """, (data_envio,))
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Erro ao obter produtos pela data de envio {data_envio}: {e}")
        return []

# --- Rotas da Aplicação --- 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nome = request.form['nome']
        senha = request.form['senha']
        usuario = verificar_usuario(nome, senha)
        if usuario:
            session['user_id'] = usuario['id']
            session['user_name'] = usuario['nome']
            session['is_admin'] = bool(usuario['admin'])
            logger.info(f"Usuário '{nome}' (ID: {usuario['id']}, Admin: {session['is_admin']}) logado com sucesso.")
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('index'))
        else:
            logger.warning(f"Tentativa de login falhou para o usuário '{nome}'.")
            flash('Nome de usuário ou senha inválidos.', 'danger')
    # Se GET ou login falhou, renderiza a página de login
    return render_template('login.html')

@app.route('/logout')
def logout():
    user_name = session.get('user_name', 'Desconhecido')
    session.clear()
    logger.info(f"Usuário '{user_name}' deslogado.")
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Simples verificação se o usuário já está logado, redireciona se estiver
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        nome = request.form['nome']
        senha = request.form['senha']
        # Validação básica (poderia ser mais robusta)
        if not nome or not senha:
            flash('Nome de usuário e senha são obrigatórios.', 'warning')
        elif registrar_usuario(nome, senha):
            logger.info(f"Novo usuário registrado: '{nome}'.")
            flash('Registro bem-sucedido! Faça o login.', 'success')
            return redirect(url_for('login'))
        else:
            logger.warning(f"Falha ao registrar usuário '{nome}' (provavelmente já existe).")
            flash('Nome de usuário já existe.', 'danger')
            
    # Se GET ou registro falhou, renderiza a página de registro
    return render_template('register.html')

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    produtos = carregar_produtos_usuario(user_id, apenas_nao_enviados=True)
    responsaveis = obter_responsaveis()
    
    # Verifica se a integração com ML está autorizada
    ml_authorized = os.path.exists(TOKEN_FILE_PATH) and load_token_data() is not None
    
    return render_template('index.html', produtos=produtos, responsaveis=responsaveis, ml_authorized=ml_authorized)

# --- ROTAS DE AUTORIZAÇÃO MERCADO LIVRE --- 

@app.route('/ml_authorize')
def ml_authorize():
    # Verifica se o usuário está logado (opcional, mas recomendado)
    if 'user_id' not in session:
        flash('Faça login para autorizar a integração com o Mercado Livre.', 'warning')
        return redirect(url_for('login'))
        
    auth_url = get_authorization_url()
    if auth_url:
        logger.info(f"Redirecionando usuário {session.get('user_name')} para autorização no Mercado Livre.")
        return redirect(auth_url)
    else:
        logger.error("Não foi possível gerar a URL de autorização do ML. Verifique as credenciais no servidor.")
        flash('Erro ao iniciar autorização com o Mercado Livre. Contate o administrador.', 'danger')
        return redirect(url_for('index'))

@app.route('/ml_callback')
def ml_callback():
    # Verifica se o usuário está logado (opcional)
    # if 'user_id' not in session:
    #     flash('Sessão expirada. Faça login novamente.', 'warning')
    #     return redirect(url_for('login'))
        
    authorization_code = request.args.get('code')
    error = request.args.get('error')
    error_description = request.args.get('error_description')

    if error:
        logger.error(f"Erro retornado pelo Mercado Livre durante autorização: {error} - {error_description}")
        flash(f'Erro na autorização do Mercado Livre: {error_description} ({error})', 'danger')
        return redirect(url_for('index'))

    if not authorization_code:
        logger.error("Callback do Mercado Livre recebido sem código de autorização.")
        flash('Erro na comunicação com o Mercado Livre (código ausente). Tente autorizar novamente.', 'danger')
        return redirect(url_for('index'))

    logger.info(f"Recebido código de autorização do ML: {authorization_code[:10]}...")
    
    # Troca o código pelo token (a função exchange_code_for_token já salva o token)
    token_data = exchange_code_for_token(authorization_code)
    
    if token_data and token_data.get('access_token'):
        logger.info(f"Autorização com Mercado Livre concluída e token salvo com sucesso.")
        flash('Integração com o Mercado Livre autorizada com sucesso!', 'success')
    else:
        logger.error("Falha ao trocar o código de autorização pelo token ou salvar o token.")
        flash('Falha ao finalizar a autorização com o Mercado Livre. Verifique os logs do servidor ou tente novamente.', 'danger')
        
    return redirect(url_for('index'))

# --- FIM ROTAS ML --- 

@app.route('/buscar_produto', methods=['POST'])
def buscar_produto():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Sessão expirada. Faça login novamente.'}), 401
        
    ean = request.form.get('ean')
    if not ean or not ean.isdigit():
        return jsonify({'success': False, 'message': 'Código EAN inválido.'}), 400
        
    user_id = session['user_id']
    
    # 1. Tenta buscar no banco de dados local primeiro
    produto_local = buscar_produto_local(ean, user_id)
    if produto_local:
        logger.info(f"Produto EAN {ean} encontrado localmente para usuário {user_id}.")
        # Retorna os dados locais, mas indica que foi local
        return jsonify({
            'success': True, 
            'data': produto_local, 
            'message': 'Produto já existe na sua lista atual.', 
            'source': 'local'
        })
        
    # 2. Se não encontrou localmente, busca online no Mercado Livre
    logger.info(f"Produto EAN {ean} não encontrado localmente. Buscando online no Mercado Livre...")
    
    # Verifica se a integração ML está autorizada antes de tentar buscar
    if not os.path.exists(TOKEN_FILE_PATH) or load_token_data() is None:
         logger.warning(f"Tentativa de busca online do EAN {ean} sem autorização do ML.")
         return jsonify({
             'success': False, 
             'message': 'A integração com o Mercado Livre não está autorizada. Clique em "Autorizar Mercado Livre" primeiro.', 
             'source': 'auth_required'
         }), 403 # Forbidden ou Bad Request?

    # Chama a função de busca online (que agora usa OAuth)
    resultado_online = buscar_produto_online(ean)
    
    # Adiciona timestamp da busca ao resultado se bem-sucedido
    if resultado_online.get('success'):
        resultado_online['data']['timestamp'] = datetime.now(timezone.utc)
        logger.info(f"Busca online para EAN {ean} retornou sucesso. Fonte: {resultado_online.get('source')}")
    else:
        logger.warning(f"Busca online para EAN {ean} falhou ou não encontrou. Mensagem: {resultado_online.get('message')}")

    # Retorna o resultado da busca online (seja sucesso ou fallback)
    return jsonify(resultado_online)

@app.route('/adicionar_produto', methods=['POST'])
def adicionar_produto():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Sessão expirada.'}), 401
        
    try:
        data = request.get_json()
        logger.debug(f"Recebido para adicionar/atualizar produto: {data}")
        
        # Validações básicas
        if not data or not data.get('ean') or not data.get('nome') or data.get('quantidade') is None:
            logger.warning(f"Dados inválidos recebidos para adicionar produto: {data}")
            return jsonify({'success': False, 'message': 'Dados incompletos ou inválidos.'}), 400
            
        produto = {
            'ean': str(data['ean']).strip(),
            'nome': str(data['nome']).strip(),
            'cor': str(data.get('cor', '')).strip(),
            'voltagem': str(data.get('voltagem', '')).strip(),
            'modelo': str(data.get('modelo', '')).strip(),
            'quantidade': int(data['quantidade']),
            'preco_medio': float(data['preco_medio']) if data.get('preco_medio') is not None else None,
            'timestamp': datetime.now(timezone.utc) # Adiciona timestamp no momento de salvar
        }
        
        # Validação adicional de quantidade
        if produto['quantidade'] <= 0:
             logger.warning(f"Quantidade inválida ({produto['quantidade']}) para EAN {produto['ean']}.")
             return jsonify({'success': False, 'message': 'Quantidade deve ser maior que zero.'}), 400

        user_id = session['user_id']
        
        if salvar_produto(produto, user_id):
            logger.info(f"Produto EAN {produto['ean']} salvo/atualizado com sucesso para usuário {user_id}.")
            # Recarrega a lista de produtos para retornar ao frontend
            produtos_atualizados = carregar_produtos_usuario(user_id, apenas_nao_enviados=True)
            # Renderiza apenas a tabela de produtos como HTML para substituir no frontend
            tabela_html = render_template('_tabela_produtos.html', produtos=produtos_atualizados, responsaveis=obter_responsaveis()) # Passa responsaveis se necessário no template
            return jsonify({'success': True, 'message': 'Produto adicionado/atualizado com sucesso!', 'table_html': tabela_html})
        else:
            logger.error(f"Falha ao salvar produto EAN {produto['ean']} no banco de dados para usuário {user_id}.")
            return jsonify({'success': False, 'message': 'Erro ao salvar produto no banco de dados.'}), 500
            
    except (ValueError, TypeError) as e:
        logger.error(f"Erro de tipo/valor ao processar dados para adicionar produto: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Erro nos dados enviados (quantidade ou preço inválido?).'}), 400
    except Exception as e:
        logger.error(f"Erro inesperado ao adicionar produto: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Erro interno no servidor.'}), 500

@app.route('/enviar_lista', methods=['POST'])
def enviar_lista():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Sessão expirada.'}), 401
        
    user_id = session['user_id']
    responsavel_id = request.form.get('responsavel_id')
    pin = request.form.get('pin')
    
    if not responsavel_id or not pin:
        return jsonify({'success': False, 'message': 'Selecione o responsável e informe o PIN.'}), 400
        
    resultado_envio = enviar_lista_produtos(user_id, responsavel_id, pin)
    
    if resultado_envio is None: # PIN inválido
        return jsonify({'success': False, 'message': 'PIN do responsável inválido.'}), 403
    elif resultado_envio == "nenhum_produto":
         return jsonify({'success': False, 'message': 'Não há produtos na lista para enviar.'}), 400
    elif resultado_envio == "erro_db" or resultado_envio == "erro_inesperado":
        return jsonify({'success': False, 'message': 'Erro ao marcar produtos como enviados no banco de dados.'}), 500
    else: # Sucesso, resultado_envio contém a data_envio
        # Recarrega a lista (que agora estará vazia)
        produtos_atualizados = carregar_produtos_usuario(user_id, apenas_nao_enviados=True)
        tabela_html = render_template('_tabela_produtos.html', produtos=produtos_atualizados, responsaveis=obter_responsaveis())
        return jsonify({'success': True, 'message': 'Lista enviada com sucesso!', 'table_html': tabela_html})

@app.route('/deletar_produto/<int:produto_id>', methods=['DELETE'])
def deletar_produto_route(produto_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Sessão expirada.'}), 401
        
    user_id = session['user_id']
    if deletar_produto(produto_id, user_id):
        logger.info(f"Usuário {user_id} deletou produto ID {produto_id}.")
        # Recarrega a lista de produtos para retornar ao frontend
        produtos_atualizados = carregar_produtos_usuario(user_id, apenas_nao_enviados=True)
        tabela_html = render_template('_tabela_produtos.html', produtos=produtos_atualizados, responsaveis=obter_responsaveis())
        return jsonify({'success': True, 'message': 'Produto deletado.', 'table_html': tabela_html})
    else:
        logger.warning(f"Falha ao deletar produto ID {produto_id} pelo usuário {user_id}.")
        return jsonify({'success': False, 'message': 'Erro ao deletar produto (pode já ter sido enviado ou não pertence a você).'}), 400

# --- Rotas de Admin --- 

@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('login'))
        
    listas_enviadas = carregar_todas_listas_enviadas()
    # Agrupar por data de envio para exibição
    listas_agrupadas = {}
    for produto in listas_enviadas:
        data_envio = produto['data_envio']
        if data_envio not in listas_agrupadas:
            listas_agrupadas[data_envio] = {
                'data_envio': data_envio,
                'nome_usuario': produto['nome_usuario'],
                'nome_responsavel': produto['nome_responsavel'],
                'validado': bool(produto['validado']),
                'nome_validador': produto['nome_validador'],
                'data_validacao': produto['data_validacao'],
                'total_itens': 0,
                'total_quantidade': 0
            }
        listas_agrupadas[data_envio]['total_itens'] += 1
        listas_agrupadas[data_envio]['total_quantidade'] += produto['quantidade']
        
    # Ordenar pela data de envio mais recente
    listas_ordenadas = sorted(listas_agrupadas.values(), key=lambda x: x['data_envio'], reverse=True)
    
    return render_template('admin.html', listas=listas_ordenadas)

@app.route('/admin/validar/<path:data_envio>', methods=['POST'])
def validar_lista_route(data_envio):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Acesso não autorizado.'}), 403
        
    validador_id = session['user_id']
    if validar_lista(data_envio, validador_id):
        logger.info(f"Admin {session['user_name']} validou a lista enviada em {data_envio}.")
        flash(f'Lista enviada em {data_brasileira_filter(data_envio)} validada com sucesso!', 'success')
        return jsonify({'success': True})
    else:
        logger.error(f"Admin {session['user_name']} falhou ao validar a lista enviada em {data_envio}.")
        return jsonify({'success': False, 'message': 'Erro ao validar a lista no banco de dados.'}), 500

@app.route('/admin/detalhes/<path:data_envio>')
def detalhes_lista(data_envio):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('login'))
        
    produtos = obter_produtos_por_data_envio(data_envio)
    if not produtos:
        flash('Lista não encontrada ou vazia.', 'warning')
        return redirect(url_for('admin'))
        
    # Pega informações gerais do primeiro produto (usuário, responsável, etc.)
    info_lista = produtos[0] 
    
    return render_template('detalhes_lista.html', produtos=produtos, info_lista=info_lista)

@app.route('/admin/exportar/<path:data_envio>')
def exportar_lista(data_envio):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('login'))
        
    produtos = obter_produtos_por_data_envio(data_envio)
    if not produtos:
        flash('Lista não encontrada ou vazia para exportar.', 'warning')
        return redirect(url_for('admin'))
        
    # Preparar dados para DataFrame
    dados_export = []
    for p in produtos:
        dados_export.append({
            'EAN': p['ean'],
            'Nome': p['nome'],
            'Cor': p.get('cor', ''),
            'Voltagem': p.get('voltagem', ''),
            'Modelo': p.get('modelo', ''),
            'Quantidade': p['quantidade'],
            'Preço Médio ML': p.get('preco_medio'),
            'Usuário': p['nome_usuario'],
            'Data Envio': data_brasileira_filter(p['data_envio']),
            'Responsável Envio': p['nome_responsavel'],
            'Validado': 'Sim' if p['validado'] else 'Não',
            'Validador': p['nome_validador'] if p['validado'] else '',
            'Data Validação': data_brasileira_filter(p['data_validacao']) if p['validado'] else ''
        })
        
    df = pd.DataFrame(dados_export)
    
    # Criar arquivo Excel na memória
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Produtos')
        # Auto-ajustar largura das colunas (opcional)
        # worksheet = writer.sheets['Produtos']
        # for i, col in enumerate(df.columns):
        #     column_len = max(df[col].astype(str).map(len).max(), len(col))
        #     worksheet.set_column(i, i, column_len)
            
    output.seek(0)
    
    # Limpar nome do arquivo
    nome_usuario = produtos[0]['nome_usuario']
    data_envio_safe = re.sub(r'[^0-9a-zA-Z-]', '_', data_envio)
    filename = f"lista_{nome_usuario}_{data_envio_safe}.xlsx"
    
    logger.info(f"Admin {session['user_name']} exportou a lista enviada em {data_envio} para o arquivo {filename}.")
    
    return send_file(output, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/admin/pesquisar', methods=['GET'])
def pesquisar_admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('login'))
        
    query = request.args.get('q', '').strip()
    resultados = []
    if query:
        resultados = pesquisar_produtos(query)
        logger.info(f"Admin {session['user_name']} pesquisou por '{query}'. {len(resultados)} resultados encontrados.")
    else:
         # Se a query for vazia, talvez redirecionar para /admin ou mostrar mensagem?
         pass 
         
    return render_template('admin_pesquisa.html', query=query, resultados=resultados)

# --- Ponto de Entrada --- 
if __name__ == '__main__':
    # Obtém a porta da variável de ambiente PORT, padrão 5000 se não definida
    port = int(os.environ.get('PORT', 5000))
    # Executa o app Flask escutando em todas as interfaces (0.0.0.0)
    # O modo debug deve ser desativado em produção!
    app.run(host='0.0.0.0', port=port, debug=False)
