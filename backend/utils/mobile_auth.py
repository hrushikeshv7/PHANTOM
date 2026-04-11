"""
Simple API key auth for PHANTØM Mobile.
Add MOBILE_API_KEY=your_secret_key to your .env on Render.
"""
from fastapi import Header, HTTPException
import os

MOBILE_API_KEY = os.getenv("MOBILE_API_KEY", "phantom-mobile-secret")

async def verify_mobile_key(x_api_key: str = Header(...)):
    if x_api_key != MOBILE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key
