from fastapi import FastAPI
app = FastAPI()

@app.post("/{action}")
async def argocd_action(action: str):
    return {"server": "argocd", "action": action, "status": "ok"}
