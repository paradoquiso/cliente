# -*- coding: utf-8 -*-
'''
Este módulo lida com a integração com a API do Mercado Livre,
utilizando o fluxo de autenticação OAuth 2.0 (Authorization Code Grant)
para obter tokens de acesso e realizar buscas de produtos por EAN.
'''
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

# --- Credenciais e Configurações --- 
# TODO: É altamente recomendável mover estas credenciais para variáveis de ambiente
# em um ambiente de produção para maior segurança.
CLIENT_ID = "4200119519362485"
CLIENT_SECRET = "m72E2336fMKGDFp7xTq2pmyt02XX1C4R"
REDIRECT_URI = "https://cliente-v9ae.onrender.com/ml_callback"

# Arquivo para persistir os dados do token
TOKEN_FILE_PATH = "/home/ubuntu/ml_token.json" # Salvar na home do ubuntu para persistência simples

# --- Funções de Gerenciamento de Token --- 

def save_token_data(token_data):
    '''
    Salva os dados do token (access_token, refresh_token, expires_at) 
    em um arquivo JSON.
    Calcula e armazena o timestamp de expiração.
    '''
    try:
        expires_in = token_data.get("expires_in", 21600) # Padrão 6 horas
        expires_at = time.time() + expires_in
        data_to_save = {
            "access_token": token_data.get("access_token"),
            "refresh_token": token_data.get("refresh_token"),
            "expires_at": expires_at,
            "obtained_at": time.time()
        }
        # Garante que o diretório exista (se TOKEN_FILE_PATH incluir subdiretórios)
        # token_dir = os.path.dirname(TOKEN_FILE_PATH)
        # if token_dir and not os.path.exists(token_dir):
        #     os.makedirs(token_dir)
            
        with open(TOKEN_FILE_PATH, "w") as f:
            json.dump(data_to_save, f, indent=2)
        logger.info(f"Dados do token salvos com sucesso em {TOKEN_FILE_PATH}. Válido até {time.ctime(expires_at)}")
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar dados do token em {TOKEN_FILE_PATH}: {str(e)}")
        return False

def load_token_data():
    '''
    Carrega os dados do token do arquivo JSON.
    Retorna um dicionário com os dados ou None se o arquivo não existir ou houver erro.
    '''
    if not os.path.exists(TOKEN_FILE_PATH):
        logger.warning(f"Arquivo de token {TOKEN_FILE_PATH} não encontrado.")
        return None
    try:
        with open(TOKEN_FILE_PATH, "r") as f:
            token_data = json.load(f)
        logger.info(f"Dados do token carregados de {TOKEN_FILE_PATH}.")
        return token_data
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Erro ao carregar ou decodificar dados do token de {TOKEN_FILE_PATH}: {str(e)}")
        # Opcional: Tentar remover/renomear arquivo corrompido
        # try:
        #     os.rename(TOKEN_FILE_PATH, TOKEN_FILE_PATH + '.corrupted')
        #     logger.warning(f"Arquivo de token corrompido renomeado para {TOKEN_FILE_PATH + '.corrupted'}")
        # except OSError as ren_err:
        #     logger.error(f"Não foi possível renomear arquivo de token corrompido: {ren_err}")
        return None
    except Exception as e:
        logger.error(f"Erro inesperado ao carregar dados do token de {TOKEN_FILE_PATH}: {str(e)}")
        return None

def get_valid_access_token():
    '''
    Obtém um access token válido, atualizando-o se necessário usando o refresh token.
    Retorna o access_token ou None se não for possível obter um token válido.
    '''
    token_data = load_token_data()
    if not token_data:
        logger.error("Nenhum dado de token encontrado. É necessário autorizar a aplicação primeiro.")
        return None

    current_time = time.time()
    expires_at = token_data.get("expires_at", 0)

    # Verifica se o token atual ainda é válido (com margem de 5 minutos)
    if current_time < expires_at - 300:
        logger.info("Usando token de acesso existente.")
        return token_data.get("access_token")

    # Se expirado, tenta usar o refresh token
    logger.info("Token de acesso expirado. Tentando atualizar usando refresh token.")
    refresh_token = token_data.get("refresh_token")
    if not refresh_token:
        logger.error("Refresh token não encontrado. É necessário reautorizar a aplicação.")
        # Opcional: remover o arquivo de token inválido
        if os.path.exists(TOKEN_FILE_PATH):
             try:
                 os.remove(TOKEN_FILE_PATH)
                 logger.info(f"Arquivo de token inválido (sem refresh token) removido: {TOKEN_FILE_PATH}")
             except OSError as rm_err:
                 logger.error(f"Erro ao remover arquivo de token inválido: {rm_err}")
        return None

    new_token_data = refresh_access_token(refresh_token)
    if new_token_data:
        if save_token_data(new_token_data):
            logger.info("Token de acesso atualizado e salvo com sucesso.")
            return new_token_data.get("access_token")
        else:
            logger.error("Falha ao salvar o token atualizado.")
            # Política de fallback: retornar o token antigo expirado? Ou None?
            # Retornar None é mais seguro para evitar usar token potencialmente inválido.
            return None 
    else:
        logger.error("Falha ao atualizar o token de acesso usando refresh token. É necessário reautorizar.")
        # O refresh token pode ter sido revogado ou expirado.
        if os.path.exists(TOKEN_FILE_PATH):
             try:
                 os.remove(TOKEN_FILE_PATH)
                 logger.info(f"Arquivo de token inválido (refresh falhou) removido: {TOKEN_FILE_PATH}")
             except OSError as rm_err:
                 logger.error(f"Erro ao remover arquivo de token inválido após falha no refresh: {rm_err}")
        return None

# --- Funções do Fluxo OAuth --- 

def get_authorization_url():
    '''
    Gera a URL de autorização para o fluxo OAuth do Mercado Livre.
    Redireciona o usuário para esta URL para iniciar o processo.
    Retorna a URL ou None se o CLIENT_ID não estiver configurado.
    '''
    if not CLIENT_ID:
        logger.error("Client ID do Mercado Livre não configurado.")
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
    '''
    Troca o código de autorização (obtido após o redirect do usuário)
    por um conjunto de tokens (access_token, refresh_token).
    Retorna um dicionário com os dados do token ou None em caso de erro.
    '''
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("Client ID ou Client Secret do Mercado Livre não configurados.")
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
            # Salva imediatamente os dados do token obtido
            if save_token_data(token_data):
                logger.info("Token inicial salvo com sucesso.")
            else:
                # Mesmo que falhe ao salvar, retorna o token para uso imediato se necessário
                logger.error("Falha ao salvar o token inicial após a troca do código.")
            return token_data
        else:
            logger.error(f"Erro ao trocar código por token: {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao trocar código por token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Exceção inesperada ao trocar código por token: {str(e)}")
        return None

def refresh_access_token(refresh_token):
    '''
    Atualiza o token de acesso usando o refresh token.
    Retorna um dicionário com os novos dados do token ou None em caso de erro.
    '''
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("Client ID ou Client Secret do Mercado Livre não configurados.")
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
            return token_data
        else:
            logger.error(f"Erro ao atualizar token: {response.status_code} - {response.text}")
            # Se o refresh token for inválido (ex: revogado), pode ser necessário reautenticar.
            if response.status_code in [400, 401]: 
                 logger.error("Refresh token inválido ou expirado. Reautorização necessária.")
                 # O arquivo de token será removido na próxima chamada a get_valid_access_token
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao atualizar token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Exceção inesperada ao atualizar token: {str(e)}")
        return None

# --- Função de Busca de Produto --- 

def fallback_busca_produto(ean, message="Não foi possível buscar informações do produto online."):
    ''' Retorna uma estrutura padrão em caso de falha na busca. '''
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

def buscar_produto_por_ean(ean):
    '''
    Busca informações de um produto pelo código EAN utilizando a API do Mercado Livre
    com autenticação OAuth (Authorization Code Grant com Refresh Token).
    Calcula o preço médio dos anúncios encontrados.
    '''
    try:
        logger.info(f"Iniciando busca para o EAN: {ean}")
        
        # 1. Obter um token de acesso válido
        access_token = get_valid_access_token()
        if not access_token:
            logger.error("Não foi possível obter token de acesso válido do ML. Verifique a autorização.")
            # Tenta gerar a URL de autorização para a mensagem de erro
            auth_url = get_authorization_url()
            auth_msg = " Autorize a aplicação acessando a URL de autorização." if auth_url else " Verifique as credenciais e a configuração do servidor."
            return fallback_busca_produto(ean, f"Falha na autenticação com o Mercado Livre.{auth_msg}")
        
        # 2. Montar Headers da Requisição
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": "ClienteApp/1.0 (OAuth; github.com/paradoquiso/cliente)" # User agent mais descritivo
        }
        
        # 3. Realizar a Busca na API (usando sites/MLB/search)
        logger.info(f"Buscando anúncios com EAN {ean} via sites/MLB/search")
        encoded_ean = urllib.parse.quote(ean)
        # Buscar por EAN e limitar a quantidade para cálculo de preço
        url_search = f"https://api.mercadolibre.com/sites/MLB/search?q={encoded_ean}&limit=10"
        
        try:
            response_search = requests.get(url_search, headers=headers, timeout=15)
            
            # 4. Processar a Resposta
            if response_search.status_code == 200:
                data_search = response_search.json()
                results_search = data_search.get("results", [])
                logger.info(f"Endpoint sites/MLB/search retornou {len(results_search)} anúncios para EAN {ean}")

                if results_search:
                    produto_encontrado = None
                    precos = []
                    
                    # Itera nos resultados para encontrar correspondência de EAN e coletar preços
                    for item in results_search:
                        atributos_item = item.get("attributes", [])
                        ean_matches = False
                        for attr in atributos_item:
                            attr_id = attr.get("id", "").upper()
                            attr_value = str(attr.get("value_name", ""))
                            # Verifica se o atributo é EAN ou GTIN e se o valor corresponde
                            if attr_id in ["EAN", "GTIN"] and attr_value == ean:
                                ean_matches = True
                                break
                        
                        # Coleta o preço do item
                        item_price = item.get("price")
                        if item_price is not None:
                             try:
                                 precos.append(float(item_price))
                             except (ValueError, TypeError):
                                 logger.warning(f"Não foi possível converter preço '{item_price}' para float no item ID {item.get('id')} para EAN {ean}")

                        # Se encontrou EAN correspondente e ainda não tem um produto principal
                        if ean_matches and not produto_encontrado:
                            produto_encontrado = item
                            logger.info(f"Anúncio com EAN {ean} correspondente encontrado: ID {item.get('id')}")
                    
                    # Se não encontrou EAN exato, usa o primeiro resultado como base
                    if not produto_encontrado and results_search:
                        produto_encontrado = results_search[0]
                        logger.info(f"Nenhum anúncio com EAN {ean} correspondente. Usando o primeiro resultado (ID: {produto_encontrado.get('id')}) como referência.")
                    elif not produto_encontrado:
                         logger.warning(f"Nenhum resultado válido encontrado na busca por EAN {ean}.")
                         return fallback_busca_produto(ean, f"Nenhum anúncio encontrado para o EAN {ean}.")

                    # Calcula o preço médio
                    preco_medio = None
                    if precos:
                        try:
                            preco_medio = round(sum(precos) / len(precos), 2)
                            logger.info(f"Preço médio calculado para EAN {ean}: R$ {preco_medio:.2f} (de {len(precos)} anúncios)")
                        except ZeroDivisionError:
                            logger.warning(f"Divisão por zero ao calcular preço médio para EAN {ean} (lista de preços vazia após filtro?).")
                        except Exception as calc_err:
                             logger.error(f"Erro ao calcular preço médio para EAN {ean}: {calc_err}")
                    else:
                        logger.warning(f"Nenhum preço válido encontrado nos anúncios para EAN {ean}.")

                    # Extrai informações do produto encontrado
                    nome_base = produto_encontrado.get("title", f"Produto {ean}")
                    permalink = produto_encontrado.get("permalink", "")
                    atributos = produto_encontrado.get("attributes", [])
                    cor, voltagem, modelo, marca = "", "", "", ""
                    
                    for attr in atributos:
                        attr_id = attr.get("id", "").upper()
                        attr_name = attr.get("name", "").upper()
                        attr_value = attr.get("value_name", "")
                        if not attr_value: continue
                        # Mapeamento mais robusto de atributos
                        if attr_id == "COLOR" or "COR" in attr_name: cor = attr_value
                        elif attr_id == "VOLTAGE" or "VOLTAGEM" in attr_name: voltagem = attr_value
                        elif attr_id == "MODEL" or "MODELO" in attr_name: modelo = attr_value
                        elif attr_id == "BRAND" or "MARCA" in attr_name: marca = attr_value
                    
                    # Limpeza básica do nome (remove atributos já extraídos)
                    nome_limpo = nome_base
                    try:
                        # Tenta remover os atributos do nome de forma segura
                        atributos_para_remover = [v for v in [cor, voltagem, modelo, marca] if v] # Lista de atributos não vazios
                        if atributos_para_remover:
                            # Cria um padrão regex para remover os atributos como palavras completas ou após hífens/barras/etc.
                            # Considera variações comuns como "Cor: Azul", "Voltagem 110v", etc.
                            pattern_str = r'(?:\b(?:Cor|Voltagem|Modelo|Marca)\s*[:\-]?\s*)?' # Prefixo opcional (ex: "Cor: ") 
                            pattern_str += r'\b(' + '|'.join(re.escape(v) for v in atributos_para_remover) + r')\b' # O atributo como palavra
                            # Removido sufixo opcional complexo que pode causar problemas
                            
                            nome_limpo = re.sub(pattern_str, '', nome_limpo, flags=re.IGNORECASE).strip()
                            # Remove espaços duplicados resultantes da substituição
                            nome_limpo = ' '.join(nome_limpo.split())
                        if not nome_limpo: nome_limpo = nome_base # Fallback se a limpeza remover tudo
                    except Exception as regex_err:
                        # Corrigido: Fechar o parêntese do logger.warning
                        logger.warning(f"Erro ao limpar nome do produto EAN {ean} com regex: {regex_err}. Usando nome base: {nome_base}")
                        nome_limpo = nome_base

                    logger.info(f"Produto EAN {ean} encontrado: Nome='{nome_limpo}', Cor='{cor}', Voltagem='{voltagem}', Modelo='{modelo}', Preço Médio={preco_medio}")
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
                    logger.warning(f"Nenhum resultado retornado na busca por EAN {ean}.")
                    return fallback_busca_produto(ean, f"Nenhum anúncio encontrado para o EAN {ean}.")
            
            # Trata erro de autenticação (token inválido/expirado que não pôde ser atualizado)
            elif response_search.status_code == 401:
                logger.error(f"Erro de autenticação (401) na API sites/search para EAN {ean}. Token inválido ou expirado. Resposta: {response_search.text}")
                # O token já foi tratado por get_valid_access_token, então o problema pode ser outro (permissões?)
                # Ou o refresh token também expirou/foi revogado.
                return fallback_busca_produto(ean, "Erro de autenticação com o Mercado Livre. Pode ser necessário reautorizar.")
            # Trata outros erros da API
            else:
                 logger.warning(f"API sites/search respondeu com status {response_search.status_code} para EAN {ean}: {response_search.text}")
                 return fallback_busca_produto(ean, f"Erro {response_search.status_code} ao consultar a API do Mercado Livre.")
        
        # Trata erros de conexão/timeout
        except requests.exceptions.Timeout:
            logger.error(f"Timeout ao buscar anúncios para EAN {ean}.")
            return fallback_busca_produto(ean, "Timeout ao conectar com a API do Mercado Livre.")
        except requests.exceptions.RequestException as req_err:
            logger.error(f"Erro de requisição na busca de anúncios (sites/search) para EAN {ean}: {str(req_err)}")
            return fallback_busca_produto(ean, f"Erro de conexão com a API do Mercado Livre: {str(req_err)}")
        except Exception as search_err:
            logger.error(f"Erro inesperado durante a busca de anúncios (sites/search) para EAN {ean}: {str(search_err)}")
            return fallback_busca_produto(ean, f"Erro inesperado ao processar busca: {str(search_err)}")

    # Trata erros gerais inesperados na função principal
    except Exception as e:
        logger.exception(f"Erro inesperado e fatal ao buscar produto por EAN {ean}: {str(e)}")
        return fallback_busca_produto(ean, f"Erro inesperado no sistema: {str(e)}")

# Exemplo de uso (para teste direto do script, requer autorização prévia)
if __name__ == '__main__':
    # 1. Verificar se existe token, senão, instruir sobre autorização
    if not os.path.exists(TOKEN_FILE_PATH):
        print(f"Arquivo de token não encontrado em: {TOKEN_FILE_PATH}")
        auth_url = get_authorization_url()
        if auth_url:
            print("\nExecute a autorização acessando a seguinte URL no seu navegador:")
            print(auth_url)
            print(f"\nApós autorizar, o Mercado Livre redirecionará para {REDIRECT_URI} com um parâmetro 'code'.")
            print("Configure a aplicação web (main.py) para estar rodando e capturar esse código na rota /ml_callback.")
            print("A rota /ml_callback chamará exchange_code_for_token, que salvará o token.")
        else:
            print("\nNão foi possível gerar a URL de autorização. Verifique as credenciais (CLIENT_ID) neste script.")
    else:
        # 2. Se o token existe, tentar buscar um EAN
        test_ean = "7891008121025" # Exemplo EAN Coca-Cola
        # test_ean = "7896094916688" # Exemplo EAN Fralda Pampers
        # test_ean = "7891150033019" # Exemplo EAN Cerveja Skol
        
        print(f"\nTestando busca para EAN: {test_ean}")
        resultado = buscar_produto_por_ean(test_ean)
        print("\nResultado da Busca:")
        print(json.dumps(resultado, indent=2, ensure_ascii=False))

        # Teste de refresh (simulado - descomente para testar se houver refresh token)
        # print("\n--- Teste de Refresh Token ---")
        # token_data = load_token_data()
        # if token_data and token_data.get('refresh_token'):
        #     print(f"Usando refresh token: {token_data['refresh_token'][:10]}...")
        #     new_token_info = refresh_access_token(token_data['refresh_token'])
        #     if new_token_info:
        #         print("Refresh bem-sucedido. Novos dados do token:")
        #         print(json.dumps(new_token_info, indent=2))
        #         # Salva o novo token (importante!)
        #         if save_token_data(new_token_info):
        #              print("Novos dados do token salvos com sucesso.")
        #         else:
        #              print("ERRO ao salvar novos dados do token.")
        #     else:
        #         print("Falha no refresh token. Pode ser necessário reautorizar.")
        # else:
        #      print("Não foi possível testar o refresh: refresh_token não encontrado no arquivo.")
