# -*- coding: utf-8 -*-
"""
Este módulo lida com a integração com a API do Mercado Livre,
realizando chamadas para autenticação e busca de produtos.

A lógica de persistência e gerenciamento de token (obter token válido, salvar, carregar)
foi movida para o módulo principal (main.py) ou um gerenciador dedicado
para evitar dependências circulares e centralizar o acesso ao banco de dados.
"""
import requests
import time
import re
import urllib.parse
import logging
import os

# Configurar logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Credenciais e Configurações --- 
# Lendo as credenciais das variáveis de ambiente
CLIENT_ID = os.environ.get("ML_CLIENT_ID")
CLIENT_SECRET = os.environ.get("ML_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("ML_REDIRECT_URI", "https://cliente-v9ae.onrender.com/ml_callback")

# Verifica se as credenciais essenciais foram carregadas
if not CLIENT_ID or not CLIENT_SECRET:
    logger.critical("### ERRO CRÍTICO: Variáveis de ambiente ML_CLIENT_ID ou ML_CLIENT_SECRET não definidas! A integração com Mercado Livre não funcionará. ###")

# --- Funções do Fluxo OAuth (Chamadas API) --- 

def get_authorization_url():
    """
    Gera a URL de autorização para o fluxo OAuth do Mercado Livre.
    Retorna a URL ou None se o CLIENT_ID ou REDIRECT_URI não estiverem configurados.
    """
    if not CLIENT_ID:
        logger.error("Client ID do Mercado Livre (ML_CLIENT_ID) não configurado.")
        return None
    if not REDIRECT_URI:
         logger.error("Redirect URI (ML_REDIRECT_URI) não configurada.")
         return None
    
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI
    }
    
    base_url = "https://auth.mercadolibre.com.br/authorization"
    auth_url = f"{base_url}?{urllib.parse.urlencode(params)}"
    
    logger.info(f"URL de autorização gerada: {auth_url}")
    return auth_url

def exchange_code_for_token(authorization_code):
    """
    Troca o código de autorização por um conjunto de tokens (access_token, refresh_token).
    Retorna um dicionário com os dados brutos do token da API ou None em caso de erro.
    NÃO salva o token aqui, a responsabilidade é do chamador (main.py).
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("Client ID ou Client Secret do ML não configurados.")
        return None
    if not REDIRECT_URI:
         logger.error("Redirect URI (ML_REDIRECT_URI) não configurada.")
         return None
    
    url = "https://api.mercadolibre.com/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": authorization_code,
        "redirect_uri": REDIRECT_URI
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        logger.info(f"Trocando código de autorização por token. Código: {authorization_code[:10]}...")
        response = requests.post(url, data=payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            token_data = response.json()
            logger.info("Token de acesso obtido com sucesso via authorization_code.")
            # Retorna os dados brutos para serem salvos pelo chamador
            return token_data 
        else:
            error_details = response.text
            logger.error(f"Erro ao trocar código por token: {response.status_code} - {error_details}")
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao trocar código por token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Exceção inesperada ao trocar código por token: {str(e)}")
        return None

def refresh_access_token(refresh_token):
    """
    Atualiza o token de acesso usando o refresh token.
    Retorna um dicionário com os novos dados brutos do token ou None em caso de erro.
    NÃO salva o token aqui, a responsabilidade é do chamador (main.py).
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("Client ID ou Client Secret do ML não configurados.")
        return None
    
    url = "https://api.mercadolibre.com/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        logger.info(f"Atualizando token de acesso usando refresh token: {refresh_token[:10]}...")
        response = requests.post(url, data=payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            token_data = response.json()
            # Importante: O ML pode ou não retornar um novo refresh_token.
            # Se não retornar, devemos continuar usando o antigo.
            if "refresh_token" not in token_data or not token_data["refresh_token"]:
                token_data["refresh_token"] = refresh_token
                logger.info("Refresh token não foi retornado na atualização, reutilizando o antigo.")
            
            logger.info("Token de acesso atualizado com sucesso via refresh_token.")
            # Retorna os dados brutos para serem salvos pelo chamador
            return token_data 
        else:
            error_details = response.text
            logger.error(f"Erro ao atualizar token: {response.status_code} - {error_details}")
            if response.status_code in [400, 401]: 
                 logger.error("Refresh token inválido ou expirado. Reautorização necessária.")
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao atualizar token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Exceção inesperada ao atualizar token: {str(e)}")
        return None

# --- Função de Busca de Produto --- 

def fallback_busca_produto(ean, message="Não foi possível buscar informações do produto online."):
    """ Retorna uma estrutura padrão em caso de falha na busca. """
    logger.warning(f"Fallback acionado para EAN: {ean}. Motivo: {message}")
    return {
        "success": False,
        "data": {
            "nome": f"Produto {ean} (não encontrado)",
            "cor": "",
            "voltagem": "",
            "modelo": "",
            "ean": ean,
            "url": "",
            "preco_medio": None
        },
        "message": message,
        "source": "fallback"
    }

def buscar_produto_por_ean(ean, access_token):
    """
    Busca informações de um produto pelo código EAN utilizando a API do Mercado Livre.
    Recebe um access_token VÁLIDO como argumento.
    Calcula o preço médio dos anúncios encontrados.
    """
    if not access_token:
        logger.error("Busca cancelada: Nenhum token de acesso fornecido.")
        return fallback_busca_produto(ean, "Token de acesso inválido ou ausente.")
        
    try:
        logger.info(f"Iniciando busca para o EAN: {ean} usando token fornecido.")
        
        # 1. Montar Headers da Requisição
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": "ClienteApp/1.0 (OAuth; github.com/paradoquiso/cliente)"
        }
        
        # 2. Realizar a Busca na API (usando sites/MLB/search)
        logger.info(f"Buscando anúncios com EAN {ean} via sites/MLB/search")
        encoded_ean = urllib.parse.quote(ean)
        # Buscar por EAN e limitar a quantidade para cálculo de preço
        url_search = f"https://api.mercadolibre.com/sites/MLB/search?official_store=all&limit=10&q={encoded_ean}"
        
        response_search = requests.get(url_search, headers=headers, timeout=15)
        
        # 3. Processar Resultados
        if response_search.status_code == 200:
            search_data = response_search.json()
            results = search_data.get("results", [])
            
            if not results:
                logger.warning(f"Nenhum anúncio encontrado para o EAN {ean} na busca.")
                return fallback_busca_produto(ean, "Nenhum anúncio encontrado para este EAN no Mercado Livre.")

            # 4. Extrair Dados do Primeiro Resultado e Calcular Preço Médio
            primeiro_produto = results[0]
            nome_produto = primeiro_produto.get("title", f"Produto {ean}")
            url_produto = primeiro_produto.get("permalink", "")
            
            # Extrair atributos (cor, voltagem, modelo) - pode precisar de ajuste fino
            atributos = {attr["name"]: attr["value_name"] for attr in primeiro_produto.get("attributes", []) if attr.get("value_name")}
            cor = atributos.get("Cor", "")
            # Tenta encontrar voltagem em diferentes nomes de atributo
            voltagem = atributos.get("Voltagem") or atributos.get("Tensão", "")
            modelo = atributos.get("Modelo", "")
            
            # Calcular preço médio
            precos = [item.get("price") for item in results if item.get("price") is not None]
            preco_medio = round(sum(precos) / len(precos), 2) if precos else None
            
            logger.info(f"Produto encontrado para EAN {ean}: ")
            logger.info(f"  Nome: {nome_produto}")
            logger.info(f"  Preço Médio: {preco_medio}")
            logger.info(f"  URL: {url_produto}")
            
            return {
                "success": True,
                "data": {
                    "nome": nome_produto,
                    "cor": cor,
                    "voltagem": voltagem,
                    "modelo": modelo,
                    "ean": ean,
                    "url": url_produto,
                    "preco_medio": preco_medio
                },
                "message": "Produto encontrado com sucesso no Mercado Livre.",
                "source": "mercado_livre_api"
            }
            
        elif response_search.status_code == 401 or response_search.status_code == 403:
             # Token pode ter expirado entre a validação e a chamada
             logger.error(f"Erro de autenticação ({response_search.status_code}) ao buscar EAN {ean}. Token pode ter expirado ou sido revogado.")
             return fallback_busca_produto(ean, f"Erro de autenticação ({response_search.status_code}) com o Mercado Livre. Tente autorizar novamente.")
        else:
            error_details = response_search.text
            logger.error(f"Erro na API do Mercado Livre ao buscar EAN {ean}: {response_search.status_code} - {error_details}")
            return fallback_busca_produto(ean, f"Erro {response_search.status_code} ao consultar API do Mercado Livre.")
            
    except requests.exceptions.Timeout:
        logger.error(f"Timeout ao buscar EAN {ean} na API do Mercado Livre.")
        return fallback_busca_produto(ean, "Tempo limite excedido ao buscar no Mercado Livre.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao buscar EAN {ean}: {str(e)}")
        return fallback_busca_produto(ean, f"Erro de rede ao conectar com Mercado Livre: {str(e)}")
    except Exception as e:
        logger.error(f"Erro inesperado ao buscar produto por EAN {ean}: {str(e)}", exc_info=True)
        return fallback_busca_produto(ean, f"Erro inesperado no servidor ao buscar produto: {str(e)}")

# --- Funções removidas (agora gerenciadas em main.py ou token_manager.py) ---
# save_token_data
# load_token_data
# get_valid_access_token
# TOKEN_FILE_PATH
