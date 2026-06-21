from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
import os

# 1. Configuração do Banco de Dados
# Substitua pela URL que você pegou no Supabase (Database > Connection string > URI)
DATABASE_URL = os.environ.get("DATABASE_URL")

engine = create_engine(DATABASE_URL)

app = FastAPI()

# 2. Habilitar CORS (permite que o seu Frontend acesse este Backend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Rota para Listar Estoque
@app.get("/estoque")
def listar_estoque():
    with engine.connect() as conn:
        query = text("SELECT * FROM componentes ORDER BY id ASC")
        result = conn.execute(query)
        # Converte as linhas do banco para uma lista de dicionários
        return [dict(row._mapping) for row in result]

# 4. Rota para Adicionar Item (Opcional)
@app.post("/estoque/adicionar")
def adicionar_item(nome: str, quantidade: int, categoria: str = None):
    with engine.begin() as conn: # engine.begin faz o commit automático
        query = text("INSERT INTO componentes (nome, quantidade, categoria) VALUES (:nome, :qtd, :cat)")
        conn.execute(query, {"nome": nome, "qtd": quantidade, "cat": categoria})
    return {"status": "sucesso"}
