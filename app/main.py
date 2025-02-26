import uvicorn
from fastapi import FastAPI
from app.routers import auth
from app.postgres_session import create_db_and_tables
from app.redis_session import redis_session

#Initiate Postgres
create_db_and_tables()

#Initiate FastAPI
app = FastAPI()
app.include_router(auth.router)

#Ping endpoint
@app.get('/')
async def ping():
    return {"status":"ok"}

#Run uvicorn
uvicorn.run(app, host='0.0.0.0', port=8080)