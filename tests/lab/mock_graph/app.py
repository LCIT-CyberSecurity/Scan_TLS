"""Throw-away Microsoft login + Graph sendMail mock for tests (never a real integration)."""
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI()
MESSAGES: list[dict] = []
SECRET = "graph-test-secret"


@app.post("/{tenant}/oauth2/v2.0/token")
def token(tenant: str, client_id: str = Form(), client_secret: str = Form(), grant_type: str = Form(""), scope: str = Form("")):
    if client_secret != SECRET:
        return JSONResponse({"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."}, status_code=401)
    return {"access_token": f"tok-{tenant}", "token_type": "Bearer", "expires_in": 3600}


@app.post("/v1.0/users/{sender}/sendMail")
async def send_mail(sender: str, request: Request, authorization: str = Header("")):
    if not authorization.startswith("Bearer tok-"):
        raise HTTPException(401, "bad token")
    if sender.startswith("forbidden"):
        return JSONResponse({"error": {"code": "ErrorAccessDenied", "message": "Access is denied."}}, status_code=403)
    body = (await request.json())["message"]
    MESSAGES.append({"sender": sender, "to": [r["emailAddress"]["address"] for r in body["toRecipients"]], "subject": body["subject"], "body": body["body"]["content"]})
    return JSONResponse(None, status_code=202)


@app.get("/messages")
def messages():
    return MESSAGES


PEOPLE = [
    {"id": "u-1", "displayName": "Alice Directory", "mail": "alice.directory@contoso.example", "userPrincipalName": "alice.directory@contoso.example"},
    {"id": "u-2", "displayName": "Bob Directory", "mail": None, "userPrincipalName": "bob.directory@contoso.example"},
    {"id": "u-3", "displayName": "Carol Other", "mail": "carol@contoso.example", "userPrincipalName": "carol@contoso.example"},
]


@app.get("/v1.0/users")
def users(request: Request, authorization: str = Header(""), top: int = 25):
    if not authorization.startswith("Bearer tok-"):
        raise HTTPException(401, "bad token")
    if "tok-denied" in authorization:
        return JSONResponse({"error": {"code": "Authorization_RequestDenied"}}, status_code=403)
    search = request.query_params.get("$search", "")
    needle = search.split(":")[1].split('"')[0].lower() if ":" in search else ""
    return {"value": [p for p in PEOPLE if not needle or needle in p["displayName"].lower() or needle in (p["mail"] or "")][:top]}
