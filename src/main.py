# -*- coding: utf-8 -*-
import sys
import os
# import sqlite3 # Removido - Usaremos PostgreSQL com SQLAlchemy
import time
from datetime import datetime, timezone, timedelta # Adicionado timedelta
import io
import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy # Adicionado SQLAlchemy
import pandas as pd
import json
from werkzeug.security import generate_password_hash, check_password_hash
from src.utils import formatar_data_brasileira
# Importar funções do módulo ML, mas a lógica de token será movida/adaptada
from src.mercado_livre import (
    get_authorization_url as ml_get_authorization_url, # Renomeado para evitar conflito
    exchange_code_for_token as ml_exchange_code_for_token,
    refresh_access_token as ml_refresh_access_token,
    buscar_produto_por_ean as buscar_produto_online,
    fallback_busca_produto,
    CLIENT_ID, # Importar para uso nas funções de token
    CLIENT_SECRET,
    REDIRECT_URI
)
import re
import logging

# Configurar logging básico
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Configuração do Banco de Dados PostgreSQL --- 
# Ler a URL do banco de dados da variável de ambiente fornecida pelo Render
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    logger.critical("### ERRO CRÍTICO: Variável de ambiente DATABASE_URL não definida! A aplicação não funcionará. Verifique a configuração no Render. ###")
    # Em um app real, talvez parar a aplicação aqui?
    # Para desenvolvimento local, você pode definir uma URL padrão:
    # DATABASE_URL = "postgresql://user:password@host:port/database"

# Ajustar a URL se ela começar com postgres:// em vez de postgresql:// (comum no Heroku/Render)
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False # Desativa warnings

db = SQLAlchemy(app)

# Chave secreta para a sessão Flask
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ean_app_secret_key_default_dev_only_unsafe")

# --- Modelos do Banco de Dados (SQLAlchemy) --- 

class Usuario(db.Model):
    __tablename__ = "usuarios"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String, unique=True, nullable=False)
    senha_hash = db.Column(db.String, nullable=False)
    admin = db.Column(db.Boolean, default=False)
    produtos = db.relationship("Produto", backref="autor", lazy=True)

class Responsavel(db.Model):
    __tablename__ = "responsaveis"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String, unique=True, nullable=False)
    pin = db.Column(db.String, nullable=False)
    produtos = db.relationship("Produto", backref="responsavel_associado", lazy=True)

class Produto(db.Model):
    __tablename__ = "produtos"
    id = db.Column(db.Integer, primary_key=True)
    ean = db.Column(db.String, nullable=False)
    nome = db.Column(db.String, nullable=False)
    cor = db.Column(db.String)
    voltagem = db.Column(db.String)
    modelo = db.Column(db.String)
    quantidade = db.Column(db.Integer, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    enviado = db.Column(db.Boolean, default=False)
    data_envio = db.Column(db.DateTime(timezone=True))
    validado = db.Column(db.Boolean, default=False)
    validador_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"))
    data_validacao = db.Column(db.DateTime(timezone=True))
    responsavel_id = db.Column(db.Integer, db.ForeignKey("responsaveis.id"))
    responsavel_pin = db.Column(db.String) # Mantido por compatibilidade, mas idealmente não seria necessário
    preco_medio = db.Column(db.Float)

    validador = db.relationship("Usuario", foreign_keys=[validador_id])

# --- NOVO MODELO PARA TOKEN MERCADO LIVRE --- 
class MercadoLivreToken(db.Model):
    __tablename__ = "mercado_livre_token"
    # Usar um ID fixo (1) para garantir que sempre haja apenas uma linha
    # Isso simplifica o carregamento e salvamento, sempre atualizamos a linha 1.
    id = db.Column(db.Integer, primary_key=True, default=1)
    access_token = db.Column(db.String, nullable=False)
    refresh_token = db.Column(db.String, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False) # Timestamp de expiração
    obtained_at = db.Column(db.DateTime(timezone=True), nullable=False) # Quando foi obtido/atualizado

# --- Funções de Gerenciamento de Token (Agora usando DB) --- 

def save_token_data_db(token_data):
    """
    Salva ou atualiza os dados do token do Mercado Livre no banco de dados.
    Calcula e armazena o timestamp de expiração.
    """
    try:
        expires_in = token_data.get("expires_in", 21600) # Padrão 6 horas
        # Calcula o tempo de expiração a partir de AGORA
        expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        obtained_at_dt = datetime.now(timezone.utc)
        
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        if not access_token or not refresh_token:
            logger.error("Tentativa de salvar token inválido (sem access ou refresh token).")
            return False

        # Tenta encontrar o token existente (deve ser sempre ID 1)
        token_entry = db.session.get(MercadoLivreToken, 1)
        
        if token_entry:
            logger.info("Atualizando token existente no banco de dados.")
            token_entry.access_token = access_token
            token_entry.refresh_token = refresh_token
            token_entry.expires_at = expires_at_dt
            token_entry.obtained_at = obtained_at_dt
        else:
            logger.info("Inserindo novo token no banco de dados (ID=1).")
            token_entry = MercadoLivreToken(
                id=1,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=expires_at_dt,
                obtained_at=obtained_at_dt
            )
            db.session.add(token_entry)
            
        db.session.commit()
        logger.info(f"Dados do token ML salvos/atualizados no DB. Válido até {expires_at_dt.isoformat()}")
        return True
    except Exception as e:
        db.session.rollback() # Desfaz a transação em caso de erro
        logger.error(f"Erro ao salvar/atualizar token ML no banco de dados: {str(e)}", exc_info=True)
        return False

def load_token_data_db():
    """
    Carrega os dados do token do banco de dados (espera-se que esteja na linha com ID=1).
    Retorna um dicionário com os dados ou None se não encontrado ou erro.
    """
    try:
        # Busca o token com ID 1
        token_entry = db.session.get(MercadoLivreToken, 1)
        
        if token_entry:
            # Converte para um dicionário compatível com o código existente
            token_data = {
                "access_token": token_entry.access_token,
                "refresh_token": token_entry.refresh_token,
                # Converter expires_at (datetime) para timestamp Unix (float) para compatibilidade
                "expires_at": token_entry.expires_at.timestamp(), 
                "obtained_at": token_entry.obtained_at.timestamp()
            }
            logger.info(f"Dados do token ML carregados do DB. Expira em: {token_entry.expires_at.isoformat()}")
            return token_data
        else:
            logger.warning("Nenhum registro de token ML encontrado no banco de dados (ID=1).")
            return None
    except Exception as e:
        logger.error(f"Erro ao carregar token ML do banco de dados: {str(e)}", exc_info=True)
        return None

def get_valid_access_token_db():
    """
    Obtém um access token válido do DB, atualizando-o via refresh token se necessário.
    Retorna o access_token ou None.
    """
    token_data = load_token_data_db()
    if not token_data:
        logger.info("Nenhum dado de token ML encontrado no DB. Autorização inicial necessária.")
        return None

    current_time = time.time() # Timestamp Unix atual
    expires_at_ts = token_data.get("expires_at", 0)

    # Verifica se o token atual ainda é válido (com margem de 5 minutos)
    if current_time < expires_at_ts - 300:
        logger.info("Usando token de acesso existente do DB.")
        return token_data.get("access_token")

    # Se expirado, tenta usar o refresh token
    logger.info("Token de acesso do DB expirado. Tentando atualizar usando refresh token.")
    refresh_token = token_data.get("refresh_token")
    if not refresh_token:
        logger.error("Refresh token não encontrado no DB. É necessário reautorizar a aplicação.")
        # Opcional: Deletar a entrada inválida do DB?
        # token_entry = db.session.get(MercadoLivreToken, 1)
        # if token_entry: 
        #     db.session.delete(token_entry)
        #     db.session.commit()
        return None

    # Chama a função original do módulo ML para fazer o refresh
    new_token_data = ml_refresh_access_token(refresh_token)
    
    if new_token_data:
        # Salva o novo token no DB
        if save_token_data_db(new_token_data):
            logger.info("Token de acesso atualizado e salvo no DB com sucesso.")
            return new_token_data.get("access_token")
        else:
            logger.error("Falha ao salvar o token atualizado no DB.")
            return None 
    else:
        logger.error("Falha ao atualizar o token de acesso usando refresh token (API ML falhou). É necessário reautorizar.")
        # O refresh token pode ter sido revogado ou expirado.
        # Opcional: Deletar a entrada inválida do DB?
        return None

# --- FIM Funções Token DB --- 

# --- Funções de Banco de Dados (Antigas - Adaptar ou Remover) --- 
# A função get_db_connection original era para SQLite. 
# Com SQLAlchemy, usamos db.session diretamente.
# Manter init_database para criar tabelas se não existirem.

def init_database_sqla():
    """Cria todas as tabelas definidas nos modelos SQLAlchemy se não existirem."""
    try:
        with app.app_context(): # Garante que estamos no contexto da aplicação
            logger.info("Verificando/Criando tabelas do banco de dados com SQLAlchemy...")
            db.create_all() # Cria tabelas: usuarios, responsaveis, produtos, mercado_livre_token
            logger.info("Tabelas verificadas/criadas.")
            
            # Inicializar dados padrão (admin, responsáveis) se necessário
            # Verificar admin
            admin_user = db.session.query(Usuario).filter_by(nome="admin").first()
            if not admin_user:
                admin_hash = generate_password_hash("admin")
                admin_user = Usuario(nome="admin", senha_hash=admin_hash, admin=True)
                db.session.add(admin_user)
                logger.info("Usuário admin padrão criado.")
            
            # Verificar responsáveis
            if db.session.query(Responsavel).count() == 0:
                responsaveis_data = [
                    {"nome": "Liliane", "pin": "5584"}, {"nome": "Rogerio", "pin": "9841"},
                    {"nome": "Celso", "pin": "2122"}, {"nome": "Marcos", "pin": "6231"}
                ]
                for r_data in responsaveis_data:
                    resp = Responsavel(nome=r_data["nome"], pin=r_data["pin"])
                    db.session.add(resp)
                logger.info(f"Responsáveis inicializados: {len(responsaveis_data)}")
            
            db.session.commit()
            logger.info("Banco de dados (SQLAlchemy) inicializado/verificado com sucesso.")
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro CRÍTICO ao inicializar o banco de dados com SQLAlchemy: {e}", exc_info=True)
        # Considerar parar a aplicação

# --- Forçar inicialização do DB ao iniciar a aplicação --- 
init_database_sqla()
# --------------------------------------------------------

# Registrar filtro Jinja2 (mantido)
@app.template_filter("data_brasileira")
def data_brasileira_filter(data):
    # ... (código do filtro mantido igual) ...
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

# --- Funções de Responsáveis e Usuários (Adaptadas para SQLAlchemy) --- 
def obter_responsaveis():
    try:
        responsaveis = db.session.query(Responsavel.id, Responsavel.nome).order_by(Responsavel.nome).all()
        # Converter para lista de dicionários para manter compatibilidade com o template
        return [{"id": r.id, "nome": r.nome} for r in responsaveis]
    except Exception as e:
        logger.error(f"Erro ao obter responsáveis (SQLAlchemy): {e}")
        return []

def verificar_pin_responsavel(responsavel_id, pin):
    try:
        responsavel = db.session.get(Responsavel, responsavel_id)
        return bool(responsavel and responsavel.pin == pin)
    except Exception as e:
        logger.error(f"Erro ao verificar PIN do responsável (SQLAlchemy): {e}")
        return False

def obter_nome_responsavel(responsavel_id):
    try:
        responsavel = db.session.get(Responsavel, responsavel_id)
        return responsavel.nome if responsavel else None
    except Exception as e:
        logger.error(f"Erro ao obter nome do responsável (SQLAlchemy): {e}")
        return None

def registrar_usuario(nome, senha):
    try:
        # Verifica se já existe
        if db.session.query(Usuario).filter_by(nome=nome).first():
            logger.warning(f"Tentativa de registrar usuário existente: {nome}")
            return False
            
        senha_hash = generate_password_hash(senha)
        novo_usuario = Usuario(nome=nome, senha_hash=senha_hash)
        db.session.add(novo_usuario)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao registrar usuário (SQLAlchemy): {e}")
        return False

def verificar_usuario(nome, senha):
    try:
        usuario = db.session.query(Usuario).filter_by(nome=nome).first()
        if usuario and check_password_hash(usuario.senha_hash, senha):
            # Retorna um dicionário para manter compatibilidade com o código que usa session
            return {
                "id": usuario.id,
                "nome": usuario.nome,
                "admin": usuario.admin
            }
        return None
    except Exception as e:
        logger.error(f"Erro ao verificar usuário (SQLAlchemy): {e}")
        return None

def obter_nome_usuario(usuario_id):
    try:
        usuario = db.session.get(Usuario, usuario_id)
        return usuario.nome if usuario else None
    except Exception as e:
        logger.error(f"Erro ao obter nome do usuário (SQLAlchemy): {e}")
        return None

# --- Funções de Produtos (Adaptadas para SQLAlchemy) --- 
def carregar_produtos_usuario(usuario_id, apenas_nao_enviados=False):
    try:
        query = db.session.query(Produto).filter_by(usuario_id=usuario_id)
        if apenas_nao_enviados:
            query = query.filter_by(enviado=False)
        produtos = query.order_by(Produto.timestamp.desc()).all()
        # Converter para lista de dicionários
        return [p.__dict__ for p in produtos] # Simplificado, pode precisar ajustar chaves _sa_instance_state
    except Exception as e:
        logger.error(f"Erro ao carregar produtos do usuário {usuario_id} (SQLAlchemy): {e}")
        return []

def carregar_todas_listas_enviadas():
    try:
        # Usar join para buscar nomes relacionados
        produtos = db.session.query(Produto, Usuario.nome.label("nome_usuario"), 
                                  Responsavel.nome.label("nome_responsavel")) \
                    .join(Usuario, Produto.usuario_id == Usuario.id) \
                    .outerjoin(Responsavel, Produto.responsavel_id == Responsavel.id) \
                    .filter(Produto.enviado == True) \
                    .order_by(Produto.data_envio.desc()).all()
        
        # Converter para lista de dicionários
        result_list = []
        for produto, nome_usuario, nome_responsavel in produtos:
            p_dict = produto.__dict__.copy()
            p_dict.pop("_sa_instance_state", None) # Remover estado SQLAlchemy
            p_dict["nome_usuario"] = nome_usuario
            p_dict["nome_responsavel"] = nome_responsavel
            # Adicionar nome do validador se existir (requer outro join ou busca separada)
            p_dict["nome_validador"] = obter_nome_usuario(produto.validador_id) if produto.validador_id else None
            result_list.append(p_dict)
        return result_list
    except Exception as e:
        logger.error(f"Erro ao carregar todas as listas enviadas (SQLAlchemy): {e}")
        return []

def pesquisar_produtos(termo_pesquisa):
    try:
        termo_like = f"%{termo_pesquisa.lower()}%"
        produtos = db.session.query(Produto, Usuario.nome.label("nome_usuario"), 
                                  Responsavel.nome.label("nome_responsavel")) \
                    .join(Usuario, Produto.usuario_id == Usuario.id) \
                    .outerjoin(Responsavel, Produto.responsavel_id == Responsavel.id) \
                    .filter(Produto.enviado == True) \
                    .filter(
                        db.or_(
                            db.func.lower(Produto.ean).like(termo_like),
                            db.func.lower(Produto.nome).like(termo_like),
                            db.func.lower(Produto.cor).like(termo_like),
                            db.func.lower(Produto.modelo).like(termo_like)
                        )
                    ) \
                    .order_by(Produto.data_envio.desc()).all()
        
        # Converter para lista de dicionários (similar a carregar_todas_listas_enviadas)
        result_list = []
        for produto, nome_usuario, nome_responsavel in produtos:
             p_dict = produto.__dict__.copy()
             p_dict.pop("_sa_instance_state", None)
             p_dict["nome_usuario"] = nome_usuario
             p_dict["nome_responsavel"] = nome_responsavel
             p_dict["nome_validador"] = obter_nome_usuario(produto.validador_id) if produto.validador_id else None
             result_list.append(p_dict)
        return result_list
    except Exception as e:
        logger.error(f"Erro ao pesquisar produtos (SQLAlchemy): {e}")
        return []

def buscar_produto_local(ean, usuario_id):
    try:
        produto = db.session.query(Produto).filter_by(ean=ean, usuario_id=usuario_id, enviado=False).first()
        return produto.__dict__ if produto else None # Retorna dict ou None
    except Exception as e:
        logger.error(f"Erro ao buscar produto local EAN {ean}, usuário {usuario_id} (SQLAlchemy): {e}")
        return None

def salvar_produto(produto_data, usuario_id):
    """ Salva ou atualiza um produto usando SQLAlchemy. produto_data é um dicionário. """
    try:
        ean = produto_data["ean"]
        quantidade_adicionar = produto_data["quantidade"]
        
        # Busca produto existente não enviado
        produto_existente = db.session.query(Produto).filter_by(ean=ean, usuario_id=usuario_id, enviado=False).first()
        
        timestamp_obj = datetime.now(timezone.utc)
        preco_medio = produto_data.get("preco_medio")

        if produto_existente:
            logger.info(f"Atualizando produto existente (ID: {produto_existente.id}) EAN: {ean} para usuário {usuario_id}.")
            produto_existente.quantidade += quantidade_adicionar
            produto_existente.timestamp = timestamp_obj
            # Atualiza outros campos se necessário (nome, cor, etc.)?
            produto_existente.nome = produto_data["nome"]
            produto_existente.cor = produto_data.get("cor")
            produto_existente.voltagem = produto_data.get("voltagem")
            produto_existente.modelo = produto_data.get("modelo")
            produto_existente.preco_medio = preco_medio
        else:
            logger.info(f"Inserindo novo produto EAN: {ean} para usuário {usuario_id}.")
            novo_produto = Produto(
                ean=ean,
                nome=produto_data["nome"],
                cor=produto_data.get("cor"),
                voltagem=produto_data.get("voltagem"),
                modelo=produto_data.get("modelo"),
                quantidade=quantidade_adicionar,
                usuario_id=usuario_id,
                timestamp=timestamp_obj,
                enviado=False,
                preco_medio=preco_medio
            )
            db.session.add(novo_produto)
            
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao salvar produto EAN {produto_data.get('ean')} (SQLAlchemy): {e}", exc_info=True)
        return False

def enviar_lista_produtos(usuario_id, responsavel_id, pin):
    try:
        if not verificar_pin_responsavel(responsavel_id, pin):
            logger.warning(f"PIN inválido para responsável ID {responsavel_id} ao enviar lista do usuário {usuario_id}.")
            return None # PIN inválido
        
        data_envio_dt = datetime.now(timezone.utc)
        
        # Atualiza produtos não enviados do usuário
        update_result = db.session.query(Produto) \
            .filter_by(usuario_id=usuario_id, enviado=False) \
            .update({
                Produto.enviado: True,
                Produto.data_envio: data_envio_dt,
                Produto.responsavel_id: responsavel_id,
                Produto.responsavel_pin: pin
            }, synchronize_session=False) # Importante para update em massa
            
        db.session.commit()
        
        affected_rows = update_result # .rowcount não funciona da mesma forma em SQLAlchemy para todos os backends
        
        if affected_rows == 0:
             logger.warning(f"Nenhum produto não enviado encontrado para usuário {usuario_id} ao tentar enviar.")
             return "nenhum_produto"
             
        logger.info(f"Produtos marcados como enviados para usuário {usuario_id}: {affected_rows}. Responsável: {responsavel_id}")
        return data_envio_dt.isoformat() # Retorna data como string ISO
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao enviar lista de produtos do usuário {usuario_id} (SQLAlchemy): {e}")
        return "erro_db"

def deletar_produto(produto_id, usuario_id):
    try:
        produto = db.session.query(Produto).filter_by(id=produto_id, usuario_id=usuario_id, enviado=False).first()
        if produto:
            db.session.delete(produto)
            db.session.commit()
            logger.info(f"Produto ID {produto_id} deletado com sucesso pelo usuário {usuario_id}.")
            return True
        else:
            logger.warning(f"Tentativa de deletar produto ID {produto_id} falhou (não encontrado, já enviado ou pertence a outro usuário). Usuário: {usuario_id}")
            return False
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao deletar produto ID {produto_id} (SQLAlchemy): {e}")
        return False

def validar_lista(data_envio_iso, validador_id):
    try:
        # Converte a string ISO de volta para datetime
        data_envio_dt = datetime.fromisoformat(data_envio_iso)
        data_validacao_dt = datetime.now(timezone.utc)
        
        update_result = db.session.query(Produto) \
            .filter(Produto.data_envio == data_envio_dt, Produto.enviado == True) \
            .update({
                Produto.validado: True,
                Produto.validador_id: validador_id,
                Produto.data_validacao: data_validacao_dt
            }, synchronize_session=False)
            
        db.session.commit()
        affected_rows = update_result
        
        if affected_rows > 0:
            logger.info(f"Lista enviada em {data_envio_iso} validada por usuário {validador_id}. {affected_rows} produtos atualizados.")
            return True
        else:
             logger.warning(f"Nenhum produto encontrado para validar com data de envio {data_envio_iso}.")
             return False
             
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao validar lista enviada em {data_envio_iso} (SQLAlchemy): {e}")
        return False

def obter_produtos_por_data_envio(data_envio_iso):
    try:
        data_envio_dt = datetime.fromisoformat(data_envio_iso)
        # Similar a carregar_todas_listas_enviadas, mas filtrando por data_envio
        produtos = db.session.query(Produto, Usuario.nome.label("nome_usuario"), 
                                  Responsavel.nome.label("nome_responsavel")) \
                    .join(Usuario, Produto.usuario_id == Usuario.id) \
                    .outerjoin(Responsavel, Produto.responsavel_id == Responsavel.id) \
                    .filter(Produto.data_envio == data_envio_dt, Produto.enviado == True) \
                    .order_by(Produto.nome).all()
        
        # Converter para lista de dicionários
        result_list = []
        for produto, nome_usuario, nome_responsavel in produtos:
             p_dict = produto.__dict__.copy()
             p_dict.pop("_sa_instance_state", None)
             p_dict["nome_usuario"] = nome_usuario
             p_dict["nome_responsavel"] = nome_responsavel
             p_dict["nome_validador"] = obter_nome_usuario(produto.validador_id) if produto.validador_id else None
             result_list.append(p_dict)
        return result_list
    except Exception as e:
        logger.error(f"Erro ao obter produtos pela data de envio {data_envio_iso} (SQLAlchemy): {e}")
        return []

# --- Rotas da Aplicação (Adaptadas para SQLAlchemy e Token DB) --- 

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form["nome"]
        senha = request.form["senha"]
        usuario = verificar_usuario(nome, senha) # Já adaptado para SQLAlchemy
        if usuario:
            session["user_id"] = usuario["id"]
            session["user_name"] = usuario["nome"]
            session["is_admin"] = bool(usuario["admin"])
            logger.info(f"Usuário '{nome}' (ID: {usuario['id']}, Admin: {session['is_admin']}) logado com sucesso.")
(Content truncated due to size limit. Use line ranges to read in chunks)
