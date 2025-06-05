# Sistema Multiusuário de Cadastro de Produtos por EAN

Este é um sistema web para cadastro de produtos por código EAN (código de barras), com persistência em banco de dados SQLite, suporte a múltiplos usuários e painel central para visualização das listas enviadas.

## Funcionalidades

- Sistema de login e cadastro de usuários
- Busca automática de informações por EAN
- Persistência de dados em banco de dados SQLite
- Priorização de busca local antes de consulta externa
- Autopreenchimento de campos para produtos já cadastrados
- Soma automática de quantidade para produtos repetidos
- Envio de listas para painel central
- Painel administrativo para visualização de todas as listas enviadas
- Exportação para Excel no formato EAN, DESCRIÇÃO, QUANTIDADE

## Requisitos

- Python 3.6 ou superior
- Flask
- SQLite
- Pandas
- Openpyxl
- Requests
- Werkzeug

## Instalação

1. Extraia o arquivo zip em seu servidor
2. Instale as dependências:
   ```
   pip install -r requirements.txt
   ```
3. Execute a aplicação:
   ```
   python src/main.py
   ```

## Uso

### Para usuários comuns:
1. Acesse a aplicação pelo navegador (por padrão em http://localhost:5000)
2. Faça login ou registre-se com nome e senha
3. Digite o código EAN no campo correspondente
4. Clique em "Buscar" para preencher automaticamente as informações
5. Ajuste qualquer informação se necessário
6. Clique em "Adicionar Produto"
7. Quando terminar de cadastrar todos os produtos, clique em "Enviar Lista"
8. A lista será enviada para o painel central e não poderá mais ser editada

### Para administradores:
1. Faça login com o usuário "admin" e senha "admin"
2. Você será redirecionado para o painel administrativo
3. No painel, você verá todas as listas enviadas pelos usuários
4. As listas são agrupadas por usuário e data de envio

## Estrutura do Projeto

- `src/main.py`: Arquivo principal da aplicação
- `src/templates/`: Templates HTML
- `produtos.db`: Banco de dados SQLite (criado automaticamente)

## Observações

- O banco de dados é criado automaticamente na primeira execução
- Um usuário administrador (admin/admin) é criado automaticamente
- Todos os produtos cadastrados ficam salvos permanentemente
- Ao digitar um EAN já cadastrado, as informações são carregadas automaticamente
- Quando o mesmo EAN é inserido novamente, a quantidade é somada automaticamente
- Após enviar uma lista para o painel central, não é possível editá-la
- Apenas usuários com privilégios de administrador podem acessar o painel central
