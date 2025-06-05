import pytz
from datetime import datetime

def formatar_data_brasileira(data):
    """
    Converte um objeto datetime para o formato brasileiro (dd/mm/aaaa HH:MM)
    com timezone America/Sao_Paulo.
    
    Args:
        data: Um objeto datetime ou string no formato ISO
        
    Returns:
        String formatada no padrão brasileiro
    """
    if not data:
        return ""
        
    # Se for string, converter para datetime
    if isinstance(data, str):
        try:
            data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            try:
                data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return data  # Retorna a string original se não conseguir converter
    
    # Verificar se é um objeto datetime
    if not isinstance(data, datetime):
        return str(data)
    
    # Definir timezone para Brasil (America/Sao_Paulo)
    timezone_brasil = pytz.timezone('America/Sao_Paulo')
    
    # Se o datetime não tem timezone, assumir UTC e converter para Brasil
    if data.tzinfo is None:
        data = pytz.utc.localize(data)
    
    # Converter para timezone do Brasil
    data_brasil = data.astimezone(timezone_brasil)
    
    # Formatar no padrão brasileiro
    return data_brasil.strftime("%d/%m/%Y %H:%M")
