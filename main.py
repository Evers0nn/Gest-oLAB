import os
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- CONFIGURAÇÕES DE SEGURANÇA (JWT e Hashing) ---
SECRET_KEY = "chave-super-secreta-territorio-do-fazer-2026" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440 # O Token dura 24 horas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_usuario_atual(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Acesso não autorizado ou Token ausente")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload 
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

# --- CONFIGURAÇÕES INICIAIS ---
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
    departamento_id: int = 1
    nivel_acesso: str = "usuario_dept"

class MovimentacaoCreate(BaseModel):
    item_id: int
    quantidade: int
    projeto: str
    tipo: str = "saida"
    data: str


# --- ROTAS DE USUÁRIOS E LOGIN (ATUALIZADAS COM SEGURANÇA) ---
@app.post("/usuarios")
def cadastrar_usuario(user: UsuarioCreate):
    try:
        check = supabase.table('usuarios').select('*').eq('usuario', user.usuario).execute()
        if len(check.data) > 0:
            raise HTTPException(status_code=400, detail="Nome de usuário já está em uso")
        
        novo_usuario = user.dict()
        novo_usuario['senha'] = get_password_hash(novo_usuario['senha'])
            
        response = supabase.table('usuarios').insert(novo_usuario).execute()
        return {"status": "sucesso", "mensagem": "Usuário criado com segurança"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/login")
def login(user: UsuarioLogin):
    try:
        response = supabase.table('usuarios').select('*').eq('usuario', user.usuario).execute()
        
        if len(response.data) == 0:
            raise HTTPException(status_code=401, detail="Usuário ou senha incorretos")
            
        usuario_db = response.data[0]
        
        if not verify_password(user.senha, usuario_db['senha']):
            raise HTTPException(status_code=401, detail="Usuário ou senha incorretos")
            
        token_data = {
            "sub": str(usuario_db['id']),
            "departamento_id": usuario_db['departamento_id'],
            "nivel_acesso": usuario_db['nivel_acesso'],
            "nome": usuario_db['nome']
        }
        access_token = create_access_token(data=token_data)
        
        del usuario_db['senha']
        
        return {
            "status": "sucesso", 
            "access_token": access_token, 
            "token_type": "bearer",
            "usuario": usuario_db
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- ROTAS DE ESTOQUE (ANTIGAS, MANTIDAS PARA O APP NÃO QUEBRAR) ---
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


# --- ROTAS DE MOVIMENTAÇÕES (ANTIGAS, MANTIDAS PARA O APP NÃO QUEBRAR) ---
@app.get("/movimentacoes")
def listar_movimentacoes():
    try:
        response = supabase.table('movimentacoes').select('*').order('id', desc=True).execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/movimentacoes")
def registrar_movimentacao(mov: MovimentacaoCreate):
    try:
        item_response = supabase.table('estoque').select('quantidade').eq('id', mov.item_id).execute()
        
        if not item_response.data:
            raise HTTPException(status_code=404, detail="Item não encontrado no estoque.")
            
        qtd_atual = item_response.data[0]['quantidade']
        
        if mov.tipo == "saida":
            if mov.quantidade > qtd_atual:
                raise HTTPException(status_code=400, detail=f"Estoque insuficiente. Disponível: {qtd_atual}")
            nova_qtd = qtd_atual - mov.quantidade
        else:
            nova_qtd = qtd_atual + mov.quantidade

        supabase.table('estoque').update({'quantidade': nova_qtd}).eq('id', mov.item_id).execute()
        
        dados_mov = mov.dict()
        if not dados_mov.get('data'):
            dados_mov['data'] = datetime.now().isoformat()
            
        mov_response = supabase.table('movimentacoes').insert(dados_mov).execute()
        
        return {"mensagem": "Saída registrada com sucesso!", "dados": mov_response.data}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
