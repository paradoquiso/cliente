'''
Este módulo inicializa a extensão SQLAlchemy e define os modelos do banco de dados.
'''
import os
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

# Inicializa a extensão SQLAlchemy sem vincular a uma aplicação Flask ainda.
# A vinculação ocorrerá em main.py com db.init_app(app).
db = SQLAlchemy()

# --- Modelos do Banco de Dados (SQLAlchemy) --- 

class Usuario(db.Model):
    __tablename__ = "usuarios"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String, unique=True, nullable=False)
    senha_hash = db.Column(db.String, nullable=False)
    admin = db.Column(db.Boolean, default=False)
    produtos = db.relationship("Produto", backref="autor", lazy=True, foreign_keys="Produto.usuario_id")
    produtos_validados = db.relationship("Produto", backref="validador_rel", lazy=True, foreign_keys="Produto.validador_id")

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
    responsavel_pin = db.Column(db.String) # Mantido por compatibilidade
    preco_medio = db.Column(db.Float)

class MercadoLivreToken(db.Model):
    __tablename__ = "mercado_livre_token"
    # Usar um ID fixo (1) para garantir que sempre haja apenas uma linha
    id = db.Column(db.Integer, primary_key=True, default=1)
    access_token = db.Column(db.String, nullable=False)
    refresh_token = db.Column(db.String, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False) # Timestamp de expiração
    obtained_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)) # Quando foi obtido/atualizado

def init_db_models(app):
    ''' Vincula o objeto db à aplicação Flask. '''
    db.init_app(app)
    logger.info("SQLAlchemy inicializado e vinculado à aplicação Flask.")

def create_tables(app):
    ''' Cria as tabelas no banco de dados se não existirem. '''
    try:
        with app.app_context():
            logger.info("Verificando/Criando tabelas do banco de dados...")
            db.create_all()
            logger.info("Tabelas verificadas/criadas com sucesso.")
            # Aqui você pode adicionar a lógica para popular dados iniciais (admin, responsaveis)
            # se necessário, de forma idempotente.
            # Exemplo:
            # if db.session.query(Usuario).filter_by(nome="admin").count() == 0:
            #     # ... criar admin ...
            #     db.session.commit()
            # if db.session.query(Responsavel).count() == 0:
            #     # ... criar responsaveis ...
            #     db.session.commit()
    except Exception as e:
        logger.error(f"Erro CRÍTICO ao criar tabelas do banco de dados: {e}", exc_info=True)
        # Considerar parar a aplicação ou lançar a exceção
        raise

