import requests
import json
import time
import re
import urllib.parse
import logging
import os

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Credenciais do Mercado Livre (Ler das variáveis de ambiente)
# Tenta ler ML_CLIENT_ID ou MERCADO_LIVRE_CLIENT_ID
CLIENT_ID = os.environ.get("ML_CLIENT_ID") or os.environ.get("MERCADO_LIVRE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("ML_CLIENT_SECRET")

# URL de callback para OAuth (pode ser configurada via variável de ambiente)
REDIRECT_URI = os.environ.get("ML_REDIRECT_URI", "http://localhost:5000/callback")

# Variável global para armazenar o token e seu tempo de expiração
_ml_token_cache = {
    "access_token": None,
    "expires_at": 0
}

def get_authorization_url():
    """
    Gera a URL de autorização para o fluxo OAuth do Mercado Livre.
    Retorna a URL ou None se as credenciais não estiverem configuradas.
    """
    if not CLIENT_ID:
        logger.error("Client ID do Mercado Livre não configurado nas variáveis de ambiente.")
        return None
    
    # Parâmetros para a URL de autorização
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI
    }
    
    # Monta a URL de autorização
    base_url = "https://auth.mercadolibre.com.br/authorization"
    auth_url = f"{base_url}?{urllib.parse.urlencode(params)}"
    
    logger.info(f"URL de autorização gerada: {auth_url}")
    return auth_url

def exchange_code_for_token(authorization_code):
    """
    Troca o código de autorização por um token de acesso.
    Retorna um dicionário com os dados do token ou None em caso de erro.
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("Client ID ou Client Secret do Mercado Livre não configurados nas variáveis de ambiente.")
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
        response = requests.post(url, data=payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            token_data = response.json()
            logger.info("Token de acesso obtido com sucesso via authorization_code.")
            return token_data
        else:
            logger.error(f"Erro ao trocar código por token: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Exceção ao trocar código por token: {str(e)}")
        return None

def refresh_access_token(refresh_token):
    """
    Atualiza o token de acesso usando o refresh token.
    Retorna um dicionário com os novos dados do token ou None em caso de erro.
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("Client ID ou Client Secret do Mercado Livre não configurados nas variáveis de ambiente.")
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
        response = requests.post(url, data=payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            token_data = response.json()
            logger.info("Token de acesso atualizado com sucesso via refresh_token.")
            return token_data
        else:
            logger.error(f"Erro ao atualizar token: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Exceção ao atualizar token: {str(e)}")
        return None

def get_ml_token_client_credentials():
    """
    Obtém um token de acesso válido para a API do Mercado Livre usando
    o fluxo client_credentials. Usa um cache simples em memória.
    Retorna o token ou None em caso de falha.
    """
    global _ml_token_cache
    current_time = time.time()

    # Verifica se o token em cache ainda é válido (com margem de 5 minutos)
    if _ml_token_cache["access_token"] and current_time < _ml_token_cache["expires_at"] - 300:
        logger.info("Usando token de acesso do Mercado Livre em cache.")
        return _ml_token_cache["access_token"]

    # Verifica se as credenciais estão configuradas
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("Client ID ou Client Secret do Mercado Livre não configurados nas variáveis de ambiente.")
        return None

    # Se o token expirou ou não existe, obtém um novo
    logger.info("Obtendo novo token de acesso do Mercado Livre via client_credentials.")
    url = "https://api.mercadolibre.com/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(url, data=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get("access_token")
            expires_in = token_data.get("expires_in", 3600) # Default 1 hora se não informado

            # Atualiza o cache
            _ml_token_cache["access_token"] = access_token
            _ml_token_cache["expires_at"] = current_time + expires_in
            
            logger.info(f"Novo token do Mercado Livre obtido com sucesso.")
            return access_token
        else:
            logger.error(f"Erro ao obter token do Mercado Livre (client_credentials): {response.status_code} - {response.text}")
            # Limpa o cache em caso de erro
            _ml_token_cache["access_token"] = None
            _ml_token_cache["expires_at"] = 0
            return None
    except Exception as e:
        logger.error(f"Exceção ao obter token do Mercado Livre (client_credentials): {str(e)}")
        # Limpa o cache em caso de erro
        _ml_token_cache["access_token"] = None
        _ml_token_cache["expires_at"] = 0
        return None

def fallback_busca_produto(ean):
    """ Retorna uma estrutura padrão em caso de falha na busca. """
    logger.warning(f"Fallback acionado para EAN: {ean}")
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
        "message": "Não foi possível buscar informações do produto online.",
        "source": "fallback"
    }

def buscar_produto_por_ean(ean):
    """
    Busca informações de um produto pelo código EAN utilizando a API do Mercado Livre
    com autenticação client_credentials e calcula o preço médio.
    """
    try:
        logger.info(f"Iniciando busca para o EAN: {ean}")
        
        access_token = get_ml_token_client_credentials()
        if not access_token:
            logger.error("Não foi possível obter token de acesso do ML. Usando fallback.")
            return fallback_busca_produto(ean)
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": "EANSearchApp/1.0 (ClientCredentials)" # User agent customizado
        }
        
        # Busca usando o endpoint sites/MLB/search (focado em anúncios para obter preço)
        logger.info(f"Buscando anúncios com EAN {ean} via sites/MLB/search")
        encoded_ean = urllib.parse.quote(ean)
        # Buscar por EAN e limitar a quantidade para cálculo de preço
        url_search = f"https://api.mercadolibre.com/sites/MLB/search?q={encoded_ean}&limit=10"
        
        try:
            response_search = requests.get(url_search, headers=headers, timeout=15)
            
            if response_search.status_code == 200:
                data_search = response_search.json()
                results_search = data_search.get("results", [])
                logger.info(f"Endpoint sites/MLB/search retornou {len(results_search)} anúncios")

                if results_search:
                    produto_encontrado = None
                    precos = []
                    
                    for item in results_search:
                        atributos_item = item.get("attributes", [])
                        ean_matches = False
                        for attr in atributos_item:
                            attr_id = attr.get("id", "").upper()
                            attr_value = str(attr.get("value_name", ""))
                            if attr_id in ["EAN", "GTIN"] and attr_value == ean:
                                ean_matches = True
                                break
                        
                        item_price = item.get("price")
                        if item_price is not None:
                             try:
                                 precos.append(float(item_price))
                             except (ValueError, TypeError):
                                 logger.warning(f"Não foi possível converter preço '{item_price}' para float no item ID {item.get('id')}")

                        if ean_matches and not produto_encontrado:
                            produto_encontrado = item
                            logger.info(f"Anúncio com EAN correspondente encontrado: ID {item.get('id')}")
                    
                    if not produto_encontrado and results_search:
                        produto_encontrado = results_search[0]
                        logger.info("Nenhum anúncio com EAN correspondente. Usando o primeiro resultado como referência.")
                    elif not produto_encontrado:
                         logger.warning(f"Nenhum resultado encontrado na busca por EAN {ean}.")
                         return fallback_busca_produto(ean)

                    preco_medio = None
                    if precos:
                        preco_medio = round(sum(precos) / len(precos), 2)
                        logger.info(f"Preço médio calculado: R$ {preco_medio:.2f} (de {len(precos)} anúncios)")
                    else:
                        logger.warning(f"Nenhum preço válido encontrado nos anúncios para EAN {ean}.")

                    nome_base = produto_encontrado.get("title", f"Produto {ean}")
                    permalink = produto_encontrado.get("permalink", "")
                    atributos = produto_encontrado.get("attributes", [])
                    cor, voltagem, modelo, marca = "", "", "", ""
                    
                    for attr in atributos:
                        attr_id = attr.get("id", "").upper()
                        attr_name = attr.get("name", "").upper()
                        attr_value = attr.get("value_name", "")
                        if not attr_value: continue
                        if attr_id == "COLOR" or "COR" in attr_name: cor = attr_value
                        elif attr_id == "VOLTAGE" or "VOLTAGEM" in attr_name: voltagem = attr_value
                        elif attr_id == "MODEL" or "MODELO" in attr_name: modelo = attr_value
                        elif attr_id == "BRAND" or "MARCA" in attr_name: marca = attr_value
                    
                    # Limpeza básica do nome
                    nome_limpo = re.sub(r'\s*-\s*(' + '|'.join(re.escape(v) for v in [cor, voltagem, modelo, marca] if v) + ')', '', nome_base, flags=re.IGNORECASE).strip()
                    nome_limpo = re.sub(r'\b(' + '|'.join(re.escape(v) for v in [cor, voltagem, modelo, marca] if v) + ')\b', '', nome_limpo, flags=re.IGNORECASE).strip()
                    nome_limpo = ' '.join(nome_limpo.split())
                    if not nome_limpo: nome_limpo = nome_base # Fallback se a limpeza remover tudo

                    logger.info(f"Produto encontrado: {nome_limpo}, Cor: {cor}, Voltagem: {voltagem}, Modelo: {modelo}, Preço Médio: {preco_medio}")
                    return {
                        "success": True,
                        "data": {
                            "nome": nome_limpo,
                            "cor": cor,
                            "voltagem": voltagem,
                            "modelo": modelo,
                            "ean": ean,
                            "url": permalink,
                            "preco_medio": preco_medio
                        },
                        "message": "Produto encontrado no Mercado Livre.",
                        "source": "mercado_livre_search"
                    }
                else:
                    logger.warning(f"Nenhum resultado encontrado na busca por EAN {ean}.")
                    return fallback_busca_produto(ean)
            
            elif response_search.status_code == 401:
                logger.error(f"Erro de autenticação (401) na API sites/search. Token inválido ou expirado. Resposta: {response_search.text}") # Log response text
                # Limpa o cache para forçar a obtenção de um novo token na próxima vez
                global _ml_token_cache
                _ml_token_cache["access_token"] = None
                _ml_token_cache["expires_at"] = 0
                return fallback_busca_produto(ean)
            else:
                 logger.warning(f"API sites/search respondeu com status {response_search.status_code}: {response_search.text}")
                 return fallback_busca_produto(ean)
        except requests.exceptions.Timeout:
            logger.error(f"Timeout ao buscar anúncios para EAN {ean}.")
            return fallback_busca_produto(ean)
        except Exception as e:
            logger.error(f"Erro na busca de anúncios (sites/search): {str(e)}")
            return fallback_busca_produto(ean)

    except Exception as e:
        logger.exception(f"Erro inesperado ao buscar produto por EAN {ean}: {str(e)}")
        return fallback_busca_produto(ean)

# Exemplo de uso (para teste direto do script)
if __name__ == '__main__':
    test_ean = "7891008121025" # Exemplo EAN Coca-Cola
    # test_ean = "7896094916688" # Exemplo EAN Fralda Pampers
    # test_ean = "7891150033019" # Exemplo EAN Cerveja Skol
    
    # Configurar variáveis de ambiente para teste local se necessário
    # os.environ['ML_CLIENT_ID'] = 'SEU_CLIENT_ID'
    # os.environ['ML_CLIENT_SECRET'] = 'SEU_CLIENT_SECRET'
    
    print(f"Testando busca para EAN: {test_ean}")
    resultado = buscar_produto_por_ean(test_ean)
    print(json.dumps(resultado, indent=2, ensure_ascii=False))
