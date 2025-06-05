# Ajustes para Deploy no Render

Este documento descreve as alterações realizadas no sistema de cadastro EAN para torná-lo compatível com a plataforma Render.

## Alterações Realizadas

1. **Criação do Procfile**
   - Foi criado um arquivo `Procfile` na raiz do projeto com o comando necessário para inicializar a aplicação no Render:
   ```
   web: gunicorn src.main:app
   ```

2. **Atualização do requirements.txt**
   - Foram adicionadas as seguintes dependências ao arquivo `requirements.txt`:
     - gunicorn==21.2.0 (servidor WSGI para produção)
     - pandas==2.1.4 (necessário para exportação Excel)
     - openpyxl==3.1.2 (necessário para exportação Excel)
     - requests==2.31.0 (necessário para busca de produtos)
     - Werkzeug==3.0.1 (necessário para autenticação)

## Estrutura do Projeto

A estrutura do projeto permanece a mesma, com a adição do arquivo Procfile:

```
sistema_cadastro_ean/
├── Procfile (NOVO)
├── README.md
├── adicionar_admin.py
├── manual_administradores.md
├── produtos.db
├── requirements.txt (ATUALIZADO)
└── src/
    ├── __init__.py
    ├── main.py
    ├── mercado_livre.py
    ├── models/
    │   └── user.py
    ├── routes/
    │   └── user.py
    ├── static/
    │   └── index.html
    └── templates/
        ├── admin.html
        ├── index.html
        ├── login.html
        └── registro.html
```

## Instruções para Deploy no Render

1. Faça upload deste projeto para o Render
2. Selecione "Web Service" como tipo de deploy
3. Configure o build command: `pip install -r requirements.txt`
4. O Render detectará automaticamente o Procfile e utilizará o comando correto para iniciar a aplicação

## Observações Importantes

- O banco de dados SQLite (`produtos.db`) está incluído no projeto e será utilizado pelo Render
- Certifique-se de que o Render tenha permissões de escrita para o diretório do banco de dados
- Para ambientes de produção com maior escala, considere migrar para um banco de dados PostgreSQL
