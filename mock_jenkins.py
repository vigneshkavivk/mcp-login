from fastapi import FastAPI
app = FastAPI()

@app.post("/{action}")
async def jenkins_action(action: str):
    return {"server": "jenkins", "action": action, "status": "ok"}
