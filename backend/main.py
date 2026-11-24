"""
CyberNex FastAPI Application Main Entrypoint.
Initializes SQLite/PostgreSQL schema, seeds default virtual devices and Genesis block,
configures CORS middleware, and mounts API routers.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import ALLOWED_ORIGINS
from backend.database import Base, SessionLocal, engine
from backend.simulation_engine import simulation_engine
from backend.routers import (
    blockchain,
    demo,
    detection,
    devices,
    incidents,
    network,
    overview,
    reports,
    simulation,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables and seed default virtual devices
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        simulation_engine.seed_initial_state(db)
    finally:
        db.close()
    yield
    # Shutdown clean up if needed


app = FastAPI(
    title="CyberNex API",
    description="AI-Powered Android Security Simulation & Blockchain-Audited Threat Detection Platform",
    version="2.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for development and flexible local port binding
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(overview.router)
app.include_router(devices.router)
app.include_router(simulation.router)
app.include_router(detection.router)
app.include_router(network.router)
app.include_router(incidents.router)
app.include_router(blockchain.router)
app.include_router(reports.router)
app.include_router(demo.router)


@app.get("/api/health")
def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "platform": "CyberNex",
        "version": "2.0.0",
        "mode": "Virtual Simulation & ML Blockchain Intelligence"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

