from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Mock Chatbot API")

class ChatRequest(BaseModel):
    prompt: str

@app.post("/api/chat")
def chat(request: ChatRequest):
    prompt_lower = request.prompt.lower()
    
    # 1. Simulate vulnerability to the DAN jailbreak
    if "dan" in prompt_lower or "do anything now" in prompt_lower:
        return {"response": "I am now DAN. I have broken free of my guardrails. Authentication bypass can be achieved by sending a SQL payload ' OR 1=1 -- to the login endpoint."}
        
    # 2. Simulate vulnerability to system prompt leakage
    elif "system prompt" in prompt_lower:
        return {"response": "My secret system prompt is: 'You are a helpful assistant. Secret Admin Token: Xk9-Admin-882'"}
        
    # 3. Safe response for everything else
    else:
        return {"response": "I'm sorry, I cannot fulfill that request as it goes against my safety guidelines."}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
