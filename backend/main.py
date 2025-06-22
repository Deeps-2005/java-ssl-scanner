from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from .analyzer import analyze_java_code
from .patcher import patch_java_code
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def health_check():
    return {"status": "ok", "message": "Backend is healthy"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    code = (await file.read()).decode()
    report = analyze_java_code(code)
    return {"report": report}

@app.post("/patch")
async def patch_java_file(file: UploadFile = File(...)):
    code = (await file.read()).decode("utf-8")
    patch_result = patch_java_code(code)
    return {
        "patched_code": patch_result["patched_code"],
        "patch_logs": patch_result["patch_logs"]
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
