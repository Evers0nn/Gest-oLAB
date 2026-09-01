import os
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt

# --- CONFIGURAÇÕES DE SEGURANÇA E JWT ---
SECRET_KEY = "chave-super-secreta-territorio-do-fazer-2026" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440 

def get_password_hash(password: str):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_usuario_atual(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente ou inválido")
    try:
        token = authorization.split(" ")[1]
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

app = FastAPI(title="API Gestão de Laboratório v3.0 - Auditoria Plena")

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

# --- FUNÇÃO DE AUDITORIA INTERNA ---
def registrar_log(usuario_nome: str, dept_id: int, acao: str):
    try:
        dept_res = supabase.table('departamentos').select('nome').eq('id', dept_id).execute()
        dept_nome = dept_res.data[0]['nome'] if dept_res.data else f"Dept {dept_id}"
        supabase.table('auditoria').insert({
            "usuario": usuario_nome,
            "departamento": dept_nome,
            "departamento_id": dept_id,
            "acao": acao
        }).execute()
    except Exception:
        pass

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
    nivel_acesso: int = 2

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
    observacao: str = ""

class SolicitacaoResposta(BaseModel):
    status: str

# --- ROTAS BÁSICAS E DEPARTAMENTOS ---
@app.get("/departamentos")
def listar_departamentos():
    try:
        return supabase.table('departamentos').select('*').execute().data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/usuarios")
def listar_usuarios(user: dict = Depends(get_usuario_atual)):
    if int(user['nivel_acesso']) > 1: return []
    return supabase.table('usuarios').select('id, nome, departamento_id').execute().data

@app.get("/auditoria")
def listar_auditoria(user: dict = Depends(get_usuario_atual)):
    nivel = int(user['nivel_acesso'])
    if nivel == 2:
        raise HTTPException(status_code=403, detail="Sem acesso ao Log.")
    try:
        query = supabase.table('auditoria').select('*').order('id', desc=True).limit(300)
        if nivel == 1: 
            query = query.eq('departamento_id', user['departamento_id'])
        return query.execute().data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- AUTENTICAÇÃO E USUÁRIOS ---
@app.post("/login")
def login(user: UsuarioLogin):
    try:
        res = supabase.table('usuarios').select('*, departamentos(nome)').eq('usuario', user.usuario).execute()
        if not res.data or not verify_password(user.senha, res.data[0]['senha']):
            raise HTTPException(status_code=401, detail="Credenciais incorretas")
            
        user_db = res.data[0]
        try:
            nivel_int = int(user_db.get('nivel_acesso', 2))
        except (ValueError, TypeError):
            nivel_int = 2

        token = create_access_token({
            "sub": str(user_db['id']),
            "departamento_id": user_db['departamento_id'],
            "nivel_acesso": nivel_int,
            "nome": user_db['nome']
        })
        del user_db['senha']
        user_db['nivel_acesso'] = nivel_int
        
        registrar_log(user_db['nome'], user_db['departamento_id'], "Realizou login no sistema.")
        return {"status": "sucesso", "access_token": token, "usuario": user_db}
    except HTTPException as e: raise e
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.post("/usuarios")
def cadastrar_usuario(user: UsuarioCreate, admin: dict = Depends(get_usuario_atual)):
    nivel_criador = int(admin['nivel_acesso'])
    
    if nivel_criador == 2:
        raise HTTPException(status_code=403, detail="Monitores (Nível 2) não podem criar usuários.")
    if nivel_criador == 1 and user.nivel_acesso < 1:
        raise HTTPException(status_code=403, detail="Responsáveis não podem criar Admin Geral.")
    
    try:
        if len(supabase.table('usuarios').select('*').eq('usuario', user.usuario).execute().data) > 0:
            raise HTTPException(status_code=400, detail="Usuário já está em uso")
        
        nome_dept = user.departamento_nome.strip()
        dept_check = supabase.table('departamentos').select('id').eq('nome', nome_dept).execute()
        
        if len(dept_check.data) > 0:
            dept_id = dept_check.data[0]['id']
        else:
            if nivel_criador != 0:
                raise HTTPException(status_code=403, detail="Apenas o Admin Geral cadastra novos departamentos.")
            novo_dept = supabase.table('departamentos').insert({"nome": nome_dept}).execute()
            dept_id = novo_dept.data[0]['id']

        if nivel_criador == 1 and dept_id != admin['departamento_id']:
            raise HTTPException(status_code=403, detail="Você só pode cadastrar no seu próprio departamento.")

        novo_usuario = {
            "nome": user.nome,
            "usuario": user.usuario,
            "senha": get_password_hash(user.senha),
            "cargo": user.cargo,
            "departamento_id": dept_id,
            "nivel_acesso": str(user.nivel_acesso)
        }
        
        supabase.table('usuarios').insert(novo_usuario).execute()
        registrar_log(admin['nome'], admin['departamento_id'], f"Cadastrou o usuário '{user.usuario}' (Nível {user.nivel_acesso}) no Dept. {nome_dept}.")
        return {"status": "sucesso", "mensagem": "Usuário criado com sucesso!"}
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
    res = supabase.table('estoque').insert(novo).execute().data
    registrar_log(user['nome'], user['departamento_id'], f"Adicionou o item '{item.nome}' ({item.quantidade} un.) ao estoque.")
    return res

@app.put("/estoque/{item_id}")
def editar_item(item_id: int, item: ItemCreate, user: dict = Depends(get_usuario_atual)):
    check = supabase.table('estoque').select('departamento_id').eq('id', item_id).execute().data
    if not check: raise HTTPException(status_code=404, detail="Item não encontrado")
    if check[0]['departamento_id'] != user['departamento_id'] and int(user['nivel_acesso']) != 0:
        raise HTTPException(status_code=403, detail="Sem permissão.")
        
    res = supabase.table('estoque').update(item.dict()).eq('id', item_id).execute().data
    registrar_log(user['nome'], user['departamento_id'], f"Atualizou o item ID {item_id} ('{item.nome}').")
    return res

@app.delete("/estoque/{item_id}")
def excluir_item(item_id: int, user: dict = Depends(get_usuario_atual)):
    nivel = int(user['nivel_acesso'])
    if nivel == 2: raise HTTPException(status_code=403, detail="Monitores não excluem itens.")
        
    check = supabase.table('estoque').select('departamento_id, nome').eq('id', item_id).execute().data
    if not check: raise HTTPException(status_code=404, detail="Não encontrado")
    
    if check[0]['departamento_id'] != user['departamento_id'] and nivel != 0:
        raise HTTPException(status_code=403, detail="Sem permissão.")
        
    supabase.table('estoque').delete().eq('id', item_id).execute()
    registrar_log(user['nome'], user['departamento_id'], f"Excluiu permanentemente o item '{check[0]['nome']}'.")
    return {"mensagem": "Ok"}

# --- ROTAS DE MOVIMENTAÇÃO ---
@app.get("/movimentacoes")
def listar_movimentacoes(user: dict = Depends(get_usuario_atual)):
    query = supabase.table('movimentacoes').select('*, usuarios(nome), departamentos(nome)').order('id', desc=True)
    if int(user['nivel_acesso']) != 0:
        query = query.eq('departamento_id', user['departamento_id'])
    return query.execute().data

@app.post("/movimentacoes")
def registrar_movimentacao(mov: MovimentacaoCreate, user: dict = Depends(get_usuario_atual)):
    item_res = supabase.table('estoque').select('*').eq('id', mov.item_id).execute().data
    if not item_res: raise HTTPException(status_code=404, detail="Item não encontrado.")
    item_db = item_res[0]
    
    if item_db['departamento_id'] != user['departamento_id'] and int(user['nivel_acesso']) != 0:
        raise HTTPException(status_code=403, detail="Pertence a outro departamento. Solicite transferência.")
        
    nova_qtd = item_db['quantidade'] - mov.quantidade if mov.tipo == "saida" else item_db['quantidade'] + mov.quantidade
    if nova_qtd < 0: raise HTTPException(status_code=400, detail="Estoque insuficiente.")
    
    supabase.table('estoque').update({'quantidade': nova_qtd}).eq('id', mov.item_id).execute()
    dados_mov = mov.dict()
    dados_mov.update({'departamento_id': item_db['departamento_id'], 'usuario_id': user['sub'], 'data': datetime.now().isoformat()})
    
    res = supabase.table('movimentacoes').insert(dados_mov).execute().data
    registrar_log(user['nome'], user['departamento_id'], f"Registrou saída de {mov.quantidade} un. de '{item_db['nome']}' para '{mov.projeto}'.")
    return res

# --- ROTAS DE SOLICITAÇÕES ---
@app.post("/solicitacoes")
def criar_solicitacao(solic: SolicitacaoCreate, user: dict = Depends(get_usuario_atual)):
    item_res = supabase.table('estoque').select('nome').eq('id', solic.item_id).execute().data
    item_nome = item_res[0]['nome'] if item_res else f"Item {solic.item_id}"

    dados = {
        "item_id": solic.item_id,
        "dept_solicitante_id": user['departamento_id'],
        "dept_solicitado_id": solic.dept_solicitado_id,
        "quantidade": solic.quantidade,
        "usuario_solicitante_id": user['sub'],
        "status": "pendente",
        "observacao": solic.observacao
    }
    supabase.table('solicitacoes').insert(dados).execute()
    registrar_log(user['nome'], user['departamento_id'], f"Solicitou {solic.quantidade} un. de '{item_nome}' do Dept ID {solic.dept_solicitado_id}.")
    return {"status": "ok"}

@app.get("/solicitacoes")
def listar_solicitacoes(user: dict = Depends(get_usuario_atual)):
    res = supabase.table('solicitacoes').select('*, usuarios(nome)').order('id', desc=True).execute().data
    if int(user['nivel_acesso']) == 0: return res
    return [s for s in res if s['dept_solicitante_id'] == user['departamento_id'] or s['dept_solicitado_id'] == user['departamento_id']]

@app.put("/solicitacoes/{id}/responder")
def responder_solicitacao(id: int, resp: SolicitacaoResposta, user: dict = Depends(get_usuario_atual)):
    nivel = int(user['nivel_acesso'])
    if nivel == 2: raise HTTPException(status_code=403, detail="Monitores não aprovam solicitações.")
        
    solic_res = supabase.table('solicitacoes').select('*').eq('id', id).execute().data
    if not solic_res: raise HTTPException(status_code=404, detail="Não encontrada.")
    solic = solic_res[0]

    if solic['status'] != 'pendente': raise HTTPException(status_code=400, detail="Já respondida.")
    if solic['dept_solicitado_id'] != user['departamento_id'] and nivel != 0: raise HTTPException(status_code=403, detail="Sem permissão.")
        
    if resp.status == 'aprovado':
        item_res = supabase.table('estoque').select('*').eq('id', solic['item_id']).execute().data
        if not item_res: raise HTTPException(status_code=404, detail="Item não encontrado no departamento.")
        item = item_res[0]

        if item['quantidade'] < solic['quantidade']:
            raise HTTPException(status_code=400, detail=f"Estoque insuficiente. Disponível: {item['quantidade']}")
        
        # Subtrai do doador
        supabase.table('estoque').update({'quantidade': item['quantidade'] - solic['quantidade']}).eq('id', solic['item_id']).execute()
        
        # Cria ou atualiza no solicitante
        item_dest = supabase.table('estoque').select('*').eq('nome', item['nome']).eq('departamento_id', solic['dept_solicitante_id']).execute().data
        if item_dest:
            supabase.table('estoque').update({'quantidade': item_dest[0]['quantidade'] + solic['quantidade']}).eq('id', item_dest[0]['id']).execute()
        else:
            novo_item = {"nome": item['nome'], "categoria": item['categoria'], "quantidade": solic['quantidade'], "quantidade_minima": 0, "localizacao": f"Transf. do Dept {solic['dept_solicitado_id']}", "departamento_id": solic['dept_solicitante_id']}
            supabase.table('estoque').insert(novo_item).execute()
        
        # Registra no histórico como Transferência (para não sujar o gráfico do Dashboard)
        supabase.table('movimentacoes').insert({
            "item_id": solic['item_id'], "quantidade": solic['quantidade'], "projeto": f"Transferência p/ Dept {solic['dept_solicitante_id']}", 
            "tipo": "transferencia", "departamento_id": solic['dept_solicitado_id'], "usuario_id": user['sub'], "data": datetime.now().isoformat()
        }).execute()

    supabase.table('solicitacoes').update({
        "status": resp.status, "data_resposta": datetime.now().isoformat(), "usuario_respondedor_id": user['sub']
    }).eq('id', id).execute()
    
    registrar_log(user['nome'], user['departamento_id'], f"{resp.status.capitalize()} a solicitação ID {id} de transferência de material.")
    return {"status": "ok"}
