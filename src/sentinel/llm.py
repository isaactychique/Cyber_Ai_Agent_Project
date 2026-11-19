import requests 

OLLAMA_URL =  "http://localhost:11434/api/chat"
MODEL = "llama3.2:3b"

def chat(messages : list[dict]) -> str : 
    response = requests.post(
        OLLAMA_URL, 
        json ={
            "model": MODEL, 
            "messages": messages, 
            "stream":  False, 
            "format": "json", 
            "options": {
                "temperature": 0
            }
        }, 
        timeout = 120
    )

    response.raise_for_status()

    result = response.json()

    return result["message"]["content"]