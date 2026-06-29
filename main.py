import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from datetime import datetime

# --- CONFIGURAÇÕES INICIAIS ---
app = FastAPI(title="API Gestão de Laboratório")

# Permite que o frontend (Vercel) comunique com o backend (Render)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conexão com o Banco de Dados (Supabase)
url = "https://pgdlhqpoywuxebtfrtrx.supabase.co"
key = "sb_publishable_smyXx5XddHo3gMozuhXF_A_MUtlkdE1"

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("Variáveis de ambiente do Supabase não encontradas!")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- MODELOS DE DADOS (PYDANTIC) ---
class ItemCreate(BaseModel):
    nome: str
    categoria: str
    quantidade: int
    localizacao: str

class UsuarioLogin(BaseModel):
    usuario: str
    senha: str

class UsuarioCreate(BaseModel):
    nome: str
    usuario: str
    senha: str
    cargo: str

class MovimentacaoCreate(BaseModel):
    item_id: int
    quantidade: int
    projeto: str
    tipo: str = "saida"
    data: str


# --- ROTAS DE ESTOQUE ---
@app.get("/estoque")
def listar_estoque():
    try:
        response = supabase.table('estoque').select('*').order('id').execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/estoque")
def cadastrar_item(item: ItemCreate):
    try:
        response = supabase.table('estoque').insert(item.dict()).execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/estoque/{item_id}")
def editar_item(item_id: int, item: ItemCreate):
    try:
        response = supabase.table('estoque').update(item.dict()).eq('id', item_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Item não encontrado")
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/estoque/{item_id}")
def excluir_item(item_id: int):
    try:
        response = supabase.table('estoque').delete().eq('id', item_id).execute()
        return {"mensagem": "Item excluído com sucesso"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- ROTAS DE MOVIMENTAÇÕES (SAÍDAS E HISTÓRICO) ---
@app.get("/movimentacoes")
def listar_movimentacoes():
    try:
        # Busca todas as movimentações, ordenando das mais recentes para as mais antigas
        response = supabase.table('movimentacoes').select('*').order('id', desc=True).execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/movimentacoes")
def registrar_movimentacao(mov: MovimentacaoCreate):
    try:
        # 1. Verifica se o item existe e qual a quantidade atual no estoque
        item_response = supabase.table('estoque').select('quantidade').eq('id', mov.item_id).execute()
        
        if not item_response.data:
            raise HTTPException(status_code=404, detail="Item não encontrado no estoque.")
            
        qtd_atual = item_response.data[0]['quantidade']
        
        # 2. Verifica se há estoque suficiente para a saída
        if mov.tipo == "saida":
            if mov.quantidade > qtd_atual:
                raise HTTPException(status_code=400, detail=f"Estoque insuficiente. Disponível: {qtd_atual}")
            nova_qtd = qtd_atual - mov.quantidade
        else:
            nova_qtd = qtd_atual + mov.quantidade

        # 3. Atualiza a quantidade na tabela de estoque
        supabase.table('estoque').update({'quantidade': nova_qtd}).eq('id', mov.item_id).execute()
        
        # 4. Registra a saída na tabela de movimentações
        dados_mov = mov.dict()
        if not dados_mov.get('data'):
            dados_mov['data'] = datetime.now().isoformat()
            
        mov_response = supabase.table('movimentacoes').insert(dados_mov).execute()
        
        return {"mensagem": "Saída registrada com sucesso!", "dados": mov_response.data}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- ROTAS DE USUÁRIOS E LOGIN ---
@app.post("/login")
def login(user: UsuarioLogin):
    try:
        response = supabase.table('usuarios').select('*').eq('usuario', user.usuario).eq('senha', user.senha).execute()
        
        if len(response.data) > 0:
            usuario_logado = response.data[0]
            del usuario_logado['senha'] # Remove a senha por segurança antes de enviar para o Front
            return {"status": "sucesso", "usuario": usuario_logado}
        else:
            return {"status": "erro", "mensagem": "Usuário ou senha incorretos"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/usuarios")
def cadastrar_usuario(user: UsuarioCreate):
    try:
        # Verifica se o usuário já existe
        check = supabase.table('usuarios').select('*').eq('usuario', user.usuario).execute()
        if len(check.data) > 0:
            raise HTTPException(status_code=400, detail="Nome de usuário já está em uso")
            
        response = supabase.table('usuarios').insert(user.dict()).execute()
        return {"status": "sucesso", "mensagem": "Usuário criado"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
