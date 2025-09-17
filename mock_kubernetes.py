from fastapi import FastAPI
app = FastAPI()

@app.post("/{action}")
async def kubernetes_action(action: str):
    return {"server": "kubernetes", "action": action, "status": "ok"}
