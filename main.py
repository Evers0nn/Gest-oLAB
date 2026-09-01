import os
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt

# --- CONFIGURAÇÕES DE SEGURANÇA ---
SECRET_KEY = "chave-super-secreta-territorio-do-fazer-2026" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440 

def get_password_hash(password: str):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_usuario_atual(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    token = authorization.split(" ")[1]
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

app = FastAPI(title="API Gestão de Laboratório v2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPABASE_URL = "https://pgdlhqpoywuxebtfrtrx.supabase.co"
SUPABASE_KEY = "sb_publishable_smyXx5XddHo3gMozuhXF_A_MUtlkdE1"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- MODELOS ---
class ItemCreate(BaseModel):
    nome: str
    categoria: str
    quantidade: int
    localizacao: str
    quantidade_minima: int = 0

class UsuarioLogin(BaseModel):
    usuario: str
    senha: str

class UsuarioCreate(BaseModel):
    nome: str
    usuario: str
    senha: str
    cargo: str
    departamento_id: int = 1
    nivel_acesso: str = "usuario_dept"

class MovimentacaoCreate(BaseModel):
    item_id: int
    quantidade: int
    projeto: str
    tipo: str = "saida"
    data: str

class SolicitacaoCreate(BaseModel):
    item_id: int
    quantidade: int
    dept_solicitado_id: int

class SolicitacaoResposta(BaseModel):
    status: str

# --- ROTAS BÁSICAS ---
@app.get("/departamentos")
def listar_departamentos():
    try:
        return supabase.table('departamentos').select('*').execute().data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/usuarios")
def cadastrar_usuario(user: UsuarioCreate):
    try:
        if len(supabase.table('usuarios').select('*').eq('usuario', user.usuario).execute().data) > 0:
            raise HTTPException(status_code=400, detail="Usuário já em uso")
        
        novo_usuario = user.dict()
        novo_usuario['senha'] = get_password_hash(novo_usuario['senha'])
        supabase.table('usuarios').insert(novo_usuario).execute()
        return {"status": "sucesso"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/login")
def login(user: UsuarioLogin):
    try:
        res = supabase.table('usuarios').select('*, departamentos(nome)').eq('usuario', user.usuario).execute()
        if not res.data or not verify_password(user.senha, res.data[0]['senha']):
            raise HTTPException(status_code=401, detail="Credenciais incorretas")
            
        user_db = res.data[0]
        token = create_access_token({"sub": str(user_db['id']), "departamento_id": user_db['departamento_id'], "nivel_acesso": user_db['nivel_acesso'], "nome": user_db['nome']})
        del user_db['senha']
        return {"status": "sucesso", "access_token": token, "usuario": user_db}
    except HTTPException as e: raise e
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

# --- ROTAS DE ESTOQUE ---
@app.get("/estoque")
def listar_estoque():
    return supabase.table('estoque').select('*, departamentos(nome)').order('id').execute().data

@app.post("/estoque")
def cadastrar_item(item: ItemCreate, user: dict = Depends(get_usuario_atual)):
    novo = item.dict()
    novo['departamento_id'] = user['departamento_id']
    return supabase.table('estoque').insert(novo).execute().data

@app.put("/estoque/{item_id}")
def editar_item(item_id: int, item: ItemCreate, user: dict = Depends(get_usuario_atual)):
    check = supabase.table('estoque').select('departamento_id').eq('id', item_id).execute().data
    if not check: raise HTTPException(status_code=404, detail="Item não encontrado")
    if check[0]['departamento_id'] != user['departamento_id'] and user['nivel_acesso'] != 'admin_geral':
        raise HTTPException(status_code=403, detail="Sem permissão.")
    return supabase.table('estoque').update(item.dict()).eq('id', item_id).execute().data

@app.delete("/estoque/{item_id}")
def excluir_item(item_id: int, user: dict = Depends(get_usuario_atual)):
    check = supabase.table('estoque').select('departamento_id').eq('id', item_id).execute().data
    if check[0]['departamento_id'] != user['departamento_id'] and user['nivel_acesso'] != 'admin_geral':
        raise HTTPException(status_code=403, detail="Sem permissão.")
    supabase.table('estoque').delete().eq('id', item_id).execute()
    return {"mensagem": "Ok"}

# --- ROTAS DE MOVIMENTAÇÃO ---
@app.get("/movimentacoes")
def listar_movimentacoes(user: dict = Depends(get_usuario_atual)):
    query = supabase.table('movimentacoes').select('*, usuarios(nome), departamentos(nome)').order('id', desc=True)
    if user['nivel_acesso'] != 'admin_geral': query = query.eq('departamento_id', user['departamento_id'])
    return query.execute().data

@app.post("/movimentacoes")
def registrar_movimentacao(mov: MovimentacaoCreate, user: dict = Depends(get_usuario_atual)):
    item_db = supabase.table('estoque').select('*').eq('id', mov.item_id).execute().data[0]
    if item_db['departamento_id'] != user['departamento_id'] and user['nivel_acesso'] != 'admin_geral':
        raise HTTPException(status_code=403, detail="Use a tela de solicitações para este item.")
        
    nova_qtd = item_db['quantidade'] - mov.quantidade if mov.tipo == "saida" else item_db['quantidade'] + mov.quantidade
    if nova_qtd < 0: raise HTTPException(status_code=400, detail="Estoque insuficiente.")
    
    supabase.table('estoque').update({'quantidade': nova_qtd}).eq('id', mov.item_id).execute()
    dados_mov = mov.dict()
    dados_mov.update({'departamento_id': user['departamento_id'], 'usuario_id': user['sub'], 'data': datetime.now().isoformat()})
    return supabase.table('movimentacoes').insert(dados_mov).execute().data

# --- ROTAS DE SOLICITAÇÕES (A MÁGICA) ---
@app.post("/solicitacoes")
def criar_solicitacao(solic: SolicitacaoCreate, user: dict = Depends(get_usuario_atual)):
    dados = {
        "item_id": solic.item_id,
        "dept_solicitante_id": user['departamento_id'],
        "dept_solicitado_id": solic.dept_solicitado_id,
        "quantidade": solic.quantidade,
        "usuario_solicitante_id": user['sub']
    }
    supabase.table('solicitacoes').insert(dados).execute()
    return {"status": "ok"}

@app.get("/solicitacoes")
def listar_solicitacoes(user: dict = Depends(get_usuario_atual)):
    res = supabase.table('solicitacoes').select('*').order('id', desc=True).execute().data
    if user['nivel_acesso'] == 'admin_geral': return res
    return [s for s in res if s['dept_solicitante_id'] == user['departamento_id'] or s['dept_solicitado_id'] == user['departamento_id']]

@app.put("/solicitacoes/{id}/responder")
def responder(id: int, resp: SolicitacaoResposta, user: dict = Depends(get_usuario_atual)):
    solic = supabase.table('solicitacoes').select('*').eq('id', id).execute().data[0]
    if solic['dept_solicitado_id'] != user['departamento_id'] and user['nivel_acesso'] != 'admin_geral':
        raise HTTPException(status_code=403, detail="Sem permissão.")
        
    if resp.status == 'aprovado':
        item = supabase.table('estoque').select('*').eq('id', solic['item_id']).execute().data[0]
        if item['quantidade'] < solic['quantidade']: raise HTTPException(status_code=400, detail="Estoque insuficiente.")
        
        # Tira do solicitado
        supabase.table('estoque').update({'quantidade': item['quantidade'] - solic['quantidade']}).eq('id', solic['item_id']).execute()
        
        # Cria no solicitante
        novo_item = {"nome": item['nome'], "categoria": item['categoria'], "quantidade": solic['quantidade'], "localizacao": f"Transferido de Dept {solic['dept_solicitado_id']}", "departamento_id": solic['dept_solicitante_id']}
        supabase.table('estoque').insert(novo_item).execute()
        
        # Registra Saída
        supabase.table('movimentacoes').insert({"item_id": solic['item_id'], "quantidade": solic['quantidade'], "projeto": f"Transferência p/ Dept {solic['dept_solicitante_id']}", "tipo": "saida", "departamento_id": solic['dept_solicitado_id'], "usuario_id": user['sub'], "data": datetime.now().isoformat()}).execute()
        
    supabase.table('solicitacoes').update({"status": resp.status, "data_resposta": datetime.now().isoformat()}).eq('id', id).execute()
    return {"status": "ok"}
