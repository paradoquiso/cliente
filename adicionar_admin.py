import os
import sys
import psycopg2
from werkzeug.security import generate_password_hash

def adicionar_admin(nome, senha):
    """Adiciona um novo usuário administrador ou promove um usuário existente."""
    # Obter a string de conexão do ambiente
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("Erro: Variável de ambiente DATABASE_URL não definida.")
        print("Defina a variável com: export DATABASE_URL=\"postgresql://ean_data_base_user:senha@host/ean_data_base?sslmode=require\"")
        sys.exit(1)
    
    try:
        # Conectar ao PostgreSQL
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # Verificar se o usuário já existe
        cursor.execute('SELECT id FROM usuarios WHERE nome = %s', (nome,))
        usuario = cursor.fetchone()
        
        if usuario:
            # Promover usuário existente a administrador
            cursor.execute('UPDATE usuarios SET admin = 1 WHERE nome = %s', (nome,))
            print(f"Usuário '{nome}' promovido a administrador com sucesso!")
        else:
            # Criar novo usuário administrador
            senha_hash = generate_password_hash(senha)
            cursor.execute('INSERT INTO usuarios (nome, senha_hash, admin) VALUES (%s, %s, %s)', 
                          (nome, senha_hash, 1))
            print(f"Novo administrador '{nome}' criado com sucesso!")
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Erro ao adicionar administrador: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Uso: python adicionar_admin.py <nome> <senha>")
        sys.exit(1)
    
    nome = sys.argv[1]
    senha = sys.argv[2]
    
    adicionar_admin(nome, senha)
