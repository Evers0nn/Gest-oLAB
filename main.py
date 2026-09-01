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
ACCESS_TOKEN_EXPIRE_MINUTES = 1440 

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

# CADEADO PRINCIPAL: Verifica quem está fazendo a requisição
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
    quantidade_minima: int = 0 # Adicionado para os alertas!

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


# --- ROTAS DE USUÁRIOS E LOGIN ---
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
        response = supabase.table('usuarios').select('*, departamentos(nome)').eq('usuario', user.usuario).execute()
        
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


# --- ROTAS DE ESTOQUE (ISOLADAS POR DEPARTAMENTO) ---
@app.get("/estoque")
def listar_estoque():
    try:
        # Traz todos os itens, mas agora puxa também o nome do departamento dono!
        response = supabase.table('estoque').select('*, departamentos(nome)').order('id').execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/estoque")
def cadastrar_item(item: ItemCreate, usuario_logado: dict = Depends(get_usuario_atual)):
    try:
        novo_item = item.dict()
        # Amarra o item ao departamento de quem está logado
        novo_item['departamento_id'] = usuario_logado['departamento_id']
        
        response = supabase.table('estoque').insert(novo_item).execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/estoque/{item_id}")
def editar_item(item_id: int, item: ItemCreate, usuario_logado: dict = Depends(get_usuario_atual)):
    try:
        check = supabase.table('estoque').select('departamento_id').eq('id', item_id).execute()
        if not check.data:
            raise HTTPException(status_code=404, detail="Item não encontrado")
        
        # Regra de Ouro: Só edita se for do seu departamento ou se você for admin_geral
        if check.data[0]['departamento_id'] != usuario_logado['departamento_id'] and usuario_logado['nivel_acesso'] != 'admin_geral':
            raise HTTPException(status_code=403, detail="Sem permissão para editar itens de outro departamento.")
            
        dados_atualizados = item.dict()
        response = supabase.table('estoque').update(dados_atualizados).eq('id', item_id).execute()
        return response.data
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/estoque/{item_id}")
def excluir_item(item_id: int, usuario_logado: dict = Depends(get_usuario_atual)):
    try:
        check = supabase.table('estoque').select('departamento_id').eq('id', item_id).execute()
        if not check.data:
            raise HTTPException(status_code=404, detail="Item não encontrado")
        
        if check.data[0]['departamento_id'] != usuario_logado['departamento_id'] and usuario_logado['nivel_acesso'] != 'admin_geral':
            raise HTTPException(status_code=403, detail="Sem permissão para excluir itens de outro departamento.")

        response = supabase.table('estoque').delete().eq('id', item_id).execute()
        return {"mensagem": "Item excluído com sucesso"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- ROTAS DE MOVIMENTAÇÕES ---
@app.get("/movimentacoes")
def listar_movimentacoes(usuario_logado: dict = Depends(get_usuario_atual)):
    try:
        # Se for admin geral, vê tudo. Se não, vê só do seu departamento.
        query = supabase.table('movimentacoes').select('*, usuarios(nome), departamentos(nome)').order('id', desc=True)
        if usuario_logado['nivel_acesso'] != 'admin_geral':
            query = query.eq('departamento_id', usuario_logado['departamento_id'])
            
        response = query.execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/movimentacoes")
def registrar_movimentacao(mov: MovimentacaoCreate, usuario_logado: dict = Depends(get_usuario_atual)):
    try:
        item_response = supabase.table('estoque').select('*').eq('id', mov.item_id).execute()
        
        if not item_response.data:
            raise HTTPException(status_code=404, detail="Item não encontrado.")
            
        item_db = item_response.data[0]
        
        # Bloqueia retirada direta de itens de outro departamento (Isso será feito via Solicitação na Fase 4)
        if item_db['departamento_id'] != usuario_logado['departamento_id'] and usuario_logado['nivel_acesso'] != 'admin_geral':
            raise HTTPException(status_code=403, detail="Este item pertence a outro departamento. Você deve solicitar uma transferência.")
            
        qtd_atual = item_db['quantidade']
        
        if mov.tipo == "saida":
            if mov.quantidade > qtd_atual:
                raise HTTPException(status_code=400, detail=f"Estoque insuficiente. Disponível: {qtd_atual}")
            nova_qtd = qtd_atual - mov.quantidade
        else:
            nova_qtd = qtd_atual + mov.quantidade

        supabase.table('estoque').update({'quantidade': nova_qtd}).eq('id', mov.item_id).execute()
        
        dados_mov = mov.dict()
        dados_mov['departamento_id'] = usuario_logado['departamento_id']
        dados_mov['usuario_id'] = usuario_logado['sub']
        if not dados_mov.get('data'):
            dados_mov['data'] = datetime.now().isoformat()
            
        mov_response = supabase.table('movimentacoes').insert(dados_mov).execute()
        return {"mensagem": "Saída registrada com sucesso!", "dados": mov_response.data}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
