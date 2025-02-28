from fastapi import APIRouter, Request, HTTPException
import secrets
import jwt
import os
import base64
from app.redis_session import redis_session
from app.postgres_session import get_session
from app.models import User
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

router = APIRouter(tags=["auth"], prefix='/auth')

SECRET_KEY = os.getenv("SECRET_KEY", "your_default_secret_key")  # Replace with your actual secret key
ALGORITHM = "HS256"

@router.post("/login")
async def login(request: Request):
    headers = request.headers
    if 'Login' not in headers or 'Password' not in headers:
        # Generate a random encryption key
        encryption_key = secrets.token_hex(16)
        
        # Save the encryption key to Redis
        redis_session.set('encryption_key', encryption_key)
        
        # Return the encryption key
        return {"encryption_key": encryption_key}
    else:
        login_encrypted = headers['Login']
        password_encrypted = headers['Password']
        
        # Get the encryption key from Redis
        encryption_key = redis_session.get('encryption_key')
        if not encryption_key:
            raise HTTPException(status_code=400, detail="Encryption key not found. Please request a new key.")
        
        # Decrypt the login and password
        login = xor_decrypt(login_encrypted, encryption_key)
        password = xor_decrypt(password_encrypted, encryption_key)
        
        # Verify user credentials
        with next(get_session()) as session:
            user = session.query(User).filter(User.login == login).first()
            if user and user.verify_password(password):
                # Generate JWT token
                access_token_expires = timedelta(minutes=30)
                access_token = create_access_token(
                    data={"sub": user.login}, expires_delta=access_token_expires
                )
                
                # Store the token in Redis
                redis_session.set(f"access_token:{user.login}", access_token)
                
                # Return the access token
                return {"access_token": access_token}
            else:
                raise HTTPException(status_code=401, detail="Unauthorized")

@router.post("/register")
async def register(request: Request):
    headers = request.headers
    if 'Login' not in headers or 'Password' not in headers:
        # Generate a random encryption key
        encryption_key = secrets.token_hex(16)
        
        # Save the encryption key to Redis
        redis_session.set('encryption_key', encryption_key)
        
        # Return the encryption key
        return {"encryption_key": encryption_key}
    else:
        login_encrypted = headers['Login']
        password_encrypted = headers['Password']
        
        # Get the encryption key from Redis
        encryption_key = redis_session.get('encryption_key')
        if not encryption_key:
            raise HTTPException(status_code=400, detail="Encryption key not found. Please request a new key.")
        
        # Decrypt the login and password
        login = xor_decrypt(login_encrypted, encryption_key)
        password = xor_decrypt(password_encrypted, encryption_key)
        
        # Check if the user already exists
        with next(get_session()) as session:
            existing_user = session.query(User).filter(User.login == login).first()
            if existing_user:
                raise HTTPException(status_code=401, detail="Email already registered")
            
            # Register the new user
            user = User(login=login)
            user.set_password(password)
            session.add(user)
            session.commit()
        
        # Return success status
        return {"status": "ok"}
    
def xor_decrypt(encrypted_text: str, key: str) -> str:
    # Decode the Base64 encoded string
    encrypted_bytes = base64.b64decode(encrypted_text)
    key_bytes = key.encode()

    # Perform XOR decryption
    decrypted_bytes = bytearray(len(encrypted_bytes))
    for i in range(len(encrypted_bytes)):
        decrypted_bytes[i] = encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)]

    return decrypted_bytes.decode()

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt