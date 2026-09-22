"""FastAPI application entrypoint for the RA3 Threat Response System."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI

from router import router

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
)
logger = logging.getLogger("ra3")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("RA3 Threat Response System starting up")
    yield
    logger.info("RA3 Threat Response System shutting down")


app = FastAPI(
    title="RA3 Threat Response System",
    description=(
        "Control / alarm-response plane for a 5G federated-learning security "
        "system. Ingests threats detected by RA1 and uses Claude function "
        "calling to select and rank mitigation actions."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router)


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "service": "RA3 Threat Response System",
        "docs": "/docs",
        "health": "/health",
    }
