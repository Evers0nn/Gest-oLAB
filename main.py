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
        raise HTTPException(status_code=401, detail="Token ausente ou inválido")
    token = authorization.split(" ")[1]
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

app = FastAPI(title="API Gestão de Laboratório v2.0 - RBAC")

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

# --- MODELOS PYDANTIC ---
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
    departamento_nome: str
    nivel_acesso: int = 2 # 0: Admin Geral, 1: Responsável, 2: Monitor

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


# --- AUTENTICAÇÃO E USUÁRIOS ---
@app.get("/departamentos")
def listar_departamentos():
    try:
        return supabase.table('departamentos').select('*').execute().data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/login")
def login(user: UsuarioLogin):
    try:
        res = supabase.table('usuarios').select('*, departamentos(nome)').eq('usuario', user.usuario).execute()
        if not res.data or not verify_password(user.senha, res.data[0]['senha']):
            raise HTTPException(status_code=401, detail="Credenciais incorretas")
            
        user_db = res.data[0]
        # Converte nivel_acesso para int por segurança
        try:
            nivel_int = int(user_db.get('nivel_acesso', 2))
        except (ValueError, TypeError):
            nivel_int = 0 if user_db.get('nivel_acesso') == 'admin_geral' else 1 if user_db.get('nivel_acesso') == 'admin_dept' else 2

        token = create_access_token({
            "sub": str(user_db['id']),
            "departamento_id": user_db['departamento_id'],
            "nivel_acesso": nivel_int,
            "nome": user_db['nome']
        })
        del user_db['senha']
        user_db['nivel_acesso'] = nivel_int
        return {"status": "sucesso", "access_token": token, "usuario": user_db}
    except HTTPException as e: raise e
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.post("/usuarios")
def cadastrar_usuario(user: UsuarioCreate, admin_logado: dict = Depends(get_usuario_atual)):
    nivel_criador = int(admin_logado['nivel_acesso'])
    
    # Nível 2 não tem permissão para cadastrar ninguém
    if nivel_criador == 2:
        raise HTTPException(status_code=403, detail="Monitores (Nível 2) não possuem permissão para criar usuários.")
    
    # Nível 1 só pode criar usuários de nível 1 ou 2, e apenas no seu próprio departamento
    if nivel_criador == 1:
        if user.nivel_acesso < 1:
            raise HTTPException(status_code=403, detail="Responsáveis (Nível 1) não podem criar administradores (Nível 0).")
    
    try:
        if len(supabase.table('usuarios').select('*').eq('usuario', user.usuario).execute().data) > 0:
            raise HTTPException(status_code=400, detail="Usuário de login já está em uso")
        
        # Obter ou criar departamento
        nome_dept = user.departamento_nome.strip()
        dept_check = supabase.table('departamentos').select('id').eq('nome', nome_dept).execute()
        
        if len(dept_check.data) > 0:
            dept_id = dept_check.data[0]['id']
        else:
            if nivel_criador != 0:
                raise HTTPException(status_code=403, detail="Apenas o Admin Geral pode registrar novos departamentos.")
            novo_dept = supabase.table('departamentos').insert({"nome": nome_dept}).execute()
            dept_id = novo_dept.data[0]['id']

        # Nível 1 só cria para o seu próprio departamento
        if nivel_criador == 1 and dept_id != admin_logado['departamento_id']:
            raise HTTPException(status_code=403, detail="Você só pode criar usuários para o seu próprio departamento.")

        novo_usuario = {
            "nome": user.nome,
            "usuario": user.usuario,
            "senha": get_password_hash(user.senha),
            "cargo": user.cargo,
            "departamento_id": dept_id,
            "nivel_acesso": str(user.nivel_acesso)
        }
        
        supabase.table('usuarios').insert(novo_usuario).execute()
        return {"status": "sucesso", "mensagem": f"Usuário nível {user.nivel_acesso} criado com sucesso!"}
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
    
    nivel = int(user['nivel_acesso'])
    if check[0]['departamento_id'] != user['departamento_id'] and nivel != 0:
        raise HTTPException(status_code=403, detail="Sem permissão para editar itens de outro departamento.")
        
    return supabase.table('estoque').update(item.dict()).eq('id', item_id).execute().data

@app.delete("/estoque/{item_id}")
def excluir_item(item_id: int, user: dict = Depends(get_usuario_atual)):
    nivel = int(user['nivel_acesso'])
    if nivel == 2:
        raise HTTPException(status_code=403, detail="Monitores (Nível 2) não podem excluir materiais.")
        
    check = supabase.table('estoque').select('departamento_id').eq('id', item_id).execute().data
    if check[0]['departamento_id'] != user['departamento_id'] and nivel != 0:
        raise HTTPException(status_code=403, detail="Sem permissão para excluir itens de outro departamento.")
        
    supabase.table('estoque').delete().eq('id', item_id).execute()
    return {"mensagem": "Item excluído com sucesso"}


# --- ROTAS DE MOVIMENTAÇÃO ---
@app.get("/movimentacoes")
def listar_movimentacoes(user: dict = Depends(get_usuario_atual)):
    query = supabase.table('movimentacoes').select('*, usuarios(nome), departamentos(nome)').order('id', desc=True)
    if int(user['nivel_acesso']) != 0:
        query = query.eq('departamento_id', user['departamento_id'])
    return query.execute().data

@app.post("/movimentacoes")
def registrar_movimentacao(mov: MovimentacaoCreate, user: dict = Depends(get_usuario_atual)):
    item_db = supabase.table('estoque').select('*').eq('id', mov.item_id).execute().data[0]
    
    if item_db['departamento_id'] != user['departamento_id'] and int(user['nivel_acesso']) != 0:
        raise HTTPException(status_code=403, detail="Este item pertence a outro departamento. Solicite uma transferência.")
        
    nova_qtd = item_db['quantidade'] - mov.quantidade if mov.tipo == "saida" else item_db['quantidade'] + mov.quantidade
    if nova_qtd < 0: raise HTTPException(status_code=400, detail="Estoque insuficiente.")
    
    supabase.table('estoque').update({'quantidade': nova_qtd}).eq('id', mov.item_id).execute()
    dados_mov = mov.dict()
    dados_mov.update({
        'departamento_id': item_db['departamento_id'],
        'usuario_id': user['sub'],
        'data': datetime.now().isoformat()
    })
    return supabase.table('movimentacoes').insert(dados_mov).execute().data


# --- ROTAS DE SOLICITAÇÕES ---
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
    if int(user['nivel_acesso']) == 0:
        return res
    return [s for s in res if s['dept_solicitante_id'] == user['departamento_id'] or s['dept_solicitado_id'] == user['departamento_id']]

@app.put("/solicitacoes/{id}/responder")
def responder_solicitacao(id: int, resp: SolicitacaoResposta, user: dict = Depends(get_usuario_atual)):
    nivel = int(user['nivel_acesso'])
    
    # Nível 2 não pode aprovar ou rejeitar
    if nivel == 2:
        raise HTTPException(status_code=403, detail="Monitores (Nível 2) não podem aprovar/rejeitar solicitações.")
        
    solic = supabase.table('solicitacoes').select('*').eq('id', id).execute().data[0]
    if solic['dept_solicitado_id'] != user['departamento_id'] and nivel != 0:
        raise HTTPException(status_code=403, detail="Sem permissão para responder solicitações de outro departamento.")
        
    if resp.status == 'aprovado':
        item = supabase.table('estoque').select('*').eq('id', solic['item_id']).execute().data[0]
        if item['quantidade'] < solic['quantidade']:
            raise HTTPException(status_code=400, detail="Estoque insuficiente no momento da aprovação.")
        
        # Subtrai do departamento solicitado
        supabase.table('estoque').update({'quantidade': item['quantidade'] - solic['quantidade']}).eq('id', solic['item_id']).execute()
        
        # Adiciona / cria no estoque do solicitante
        novo_item = {
            "nome": item['nome'],
            "categoria": item['categoria'],
            "quantidade": solic['quantidade'],
            "localizacao": f"Transferido de Dept {solic['dept_solicitado_id']}",
            "departamento_id": solic['dept_solicitante_id']
        }
        supabase.table('estoque').insert(novo_item).execute()
        
        # Histórico de movimentação
        supabase.table('movimentacoes').insert({
            "item_id": solic['item_id'],
            "quantidade": solic['quantidade'],
            "projeto": f"Transferência aprovada p/ Dept {solic['dept_solicitante_id']}",
            "tipo": "saida",
            "departamento_id": solic['dept_solicitado_id'],
            "usuario_id": user['sub'],
            "data": datetime.now().isoformat()
        }).execute()
        
    supabase.table('solicitacoes').update({
        "status": resp.status,
        "data_resposta": datetime.now().isoformat()
    }).execute()
    
    return {"status": "ok"}
