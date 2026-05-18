from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from agents import run_pipeline
import uvicorn
import os

app = FastAPI(title="NEXUS Multi-Agent System")

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def home():
    html_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


class QueryRequest(BaseModel):
    query: str


@app.post("/api/run")
async def run_query(body: QueryRequest):
    if not body.query or not body.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    if len(body.query) > 2000:
        raise HTTPException(status_code=400, detail="Query too long (max 2000 chars)")
    try:
        result = run_pipeline(body.query.strip())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "ok", "system": "NEXUS Multi-Agent Intelligence System"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)