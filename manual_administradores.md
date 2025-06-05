# Manual para Adicionar Novos Administradores

Este manual explica como adicionar novos administradores ao Sistema Multiusuário de Cadastro de Produtos por EAN.

## Introdução

O sistema possui dois tipos de usuários:
1. **Usuários comuns**: podem cadastrar produtos e enviar listas
2. **Administradores**: podem acessar o painel central, visualizar todas as listas enviadas, validar listas e pesquisar produtos

Por padrão, o sistema cria automaticamente um usuário administrador com as credenciais:
- Usuário: `admin`
- Senha: `admin`

## Métodos para Adicionar Novos Administradores

Existem duas maneiras de adicionar novos administradores ao sistema:

### Método 1: Usando o SQLite diretamente

1. Acesse o servidor onde o sistema está instalado
2. Abra o terminal e navegue até a pasta do projeto
3. Execute o seguinte comando para acessar o banco de dados:
   ```
   sqlite3 produtos.db
   ```
4. Para promover um usuário existente a administrador, execute:
   ```sql
   UPDATE usuarios SET admin = 1 WHERE nome = 'nome_do_usuario';
   ```
5. Para verificar se a alteração foi aplicada:
   ```sql
   SELECT id, nome, admin FROM usuarios;
   ```
6. Para sair do SQLite, digite:
   ```
   .quit
   ```

### Método 2: Usando Python

1. Crie um arquivo chamado `adicionar_admin.py` na pasta raiz do projeto com o seguinte conteúdo:

```python
import sqlite3
import os
import sys
from werkzeug.security import generate_password_hash

# Caminho para o banco de dados SQLite
DB_FILE = 'produtos.db'

def adicionar_admin(nome, senha):
    """Adiciona um novo usuário administrador ou promove um usuário existente."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Verificar se o usuário já existe
    cursor.execute('SELECT id FROM usuarios WHERE nome = ?', (nome,))
    usuario = cursor.fetchone()
    
    if usuario:
        # Promover usuário existente a administrador
        cursor.execute('UPDATE usuarios SET admin = 1 WHERE nome = ?', (nome,))
        print(f"Usuário '{nome}' promovido a administrador com sucesso!")
    else:
        # Criar novo usuário administrador
        senha_hash = generate_password_hash(senha)
        cursor.execute('INSERT INTO usuarios (nome, senha_hash, admin) VALUES (?, ?, 1)', 
                      (nome, senha_hash))
        print(f"Novo administrador '{nome}' criado com sucesso!")
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Uso: python adicionar_admin.py <nome> <senha>")
        sys.exit(1)
    
    nome = sys.argv[1]
    senha = sys.argv[2]
    
    adicionar_admin(nome, senha)
```

2. Execute o script para adicionar um novo administrador:
   ```
   python adicionar_admin.py novo_admin senha123
   ```

3. O script verificará se o usuário já existe:
   - Se existir, será promovido a administrador
   - Se não existir, será criado como um novo usuário administrador

## Verificação

Para verificar se um usuário tem privilégios de administrador:

1. Faça login com as credenciais do usuário
2. Se o usuário for administrador, será redirecionado automaticamente para o painel administrativo
3. Se não for administrador, será redirecionado para a página de cadastro de produtos

## Observações Importantes

- Mantenha as credenciais de administrador em local seguro
- Recomenda-se alterar a senha do administrador padrão (admin/admin) após a primeira instalação
- Apenas conceda privilégios de administrador a usuários confiáveis, pois eles terão acesso a todas as listas enviadas por todos os usuários
- O painel administrativo permite validar listas e pesquisar produtos por EAN ou palavra-chave
