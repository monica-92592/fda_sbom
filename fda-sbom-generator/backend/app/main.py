from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "FDA SBOM Generator"
    app_version: str = "1.0.0"
    debug: bool = True
    
    class Config:
        env_file = ".env"

settings = Settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="FDA-compliant Software Bill of Materials generator for medical devices"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "message": "FDA SBOM Generator API",
        "version": settings.app_version,
        "status": "running"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


