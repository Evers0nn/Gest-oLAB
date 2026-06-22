from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from supabase import create_client
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# COLOQUE SUAS CHAVES AQUI NOVAMENTE
url = "https://pgdlhqpoywuxebtfrtrx.supabase.co"
key = "sb_publishable_smyXx5XddHo3gMozuhXF_A_MUtlkdE1"
supabase = create_client(url, key)

class LoginData(BaseModel):
    usuario: str
    senha: str

class UsuarioNovo(BaseModel):
    usuario: str
    senha: str
    nome: str
    cargo: Optional[str] = None

class ItemEstoque(BaseModel):
    nome: str
    categoria: str
    quantidade: int
    localizacao: str

@app.get("/estoque")
def get_estoque():
    response = supabase.table("estoque").select("*").order("id").execute()
    return response.data

@app.post("/estoque")
def add_item(item: ItemEstoque):
    response = supabase.table("estoque").insert(item.dict()).execute()
    return response.data

@app.delete("/estoque/{item_id}")
def delete_item(item_id: int):
    response = supabase.table("estoque").delete().eq("id", item_id).execute()
    return response.data

# NOVA ROTA: Editar item existente
@app.put("/estoque/{item_id}")
def update_item(item_id: int, item: ItemEstoque):
    response = supabase.table("estoque").update(item.dict()).eq("id", item_id).execute()
    return response.data

@app.post("/login")
def login(data: LoginData):
    user = supabase.table("usuarios").select("*").eq("usuario", data.usuario).eq("senha", data.senha).execute()
    if len(user.data) > 0:
        return {"status": "sucesso", "usuario": user.data[0]}
    raise HTTPException(status_code=401, detail="Usuário ou senha incorretos")

@app.post("/usuarios")
def criar_usuario(user: UsuarioNovo):
    response = supabase.table("usuarios").insert(user.dict()).execute()
    return response.data
