#!/usr/bin/python3.8

import os
import typing
import typing_extensions
import threading
import asyncio
import json
import fastapi

from contextlib import asynccontextmanager
from starlette.responses import JSONResponse
import pydantic
import fastapi.openapi.utils
import dpi_swagger


class EmptyResponse(pydantic.BaseModel) :
  pass


def run_loop(loop) :
  asyncio.set_event_loop(loop)
  loop.run_forever()


global_loop = None
user_storage_server = None


class ErrorResponse(pydantic.BaseModel):
  status: int = 0,
  code: int = 0
  error: str = ''


app = fastapi.FastAPI(
  openapi_url = None, #'/rest/docs/openapi.json',
  docs_url = None, # '/rest/docs',
  swagger_ui_parameters = { "defaultModelsExpandDepth": -1 },
  tags_metadata = [
  ]
)


# public
app.include_router(dpi_swagger.get_user.router)


def custom_openapi():
  if app.openapi_schema:
    return app.openapi_schema

  openapi_schema = fastapi.openapi.utils.get_openapi(
    title = app.title,
    version = app.version,
    routes = app.routes
  )

  http_methods = ["post", "get", "put", "delete"]
  # look for the error 422 and removes it
  for method in openapi_schema["paths"]:
    for m in http_methods:
      try:
        del openapi_schema["paths"][method][m]["responses"]["422"]
      except KeyError:
        pass

  app.openapi_schema = openapi_schema
  return app.openapi_schema

app.openapi = custom_openapi

security = fastapi.security.HTTPBasic()

@app.get('/rest/docs/openapi.json', include_in_schema = False)
async def openapi(credentials: fastapi.security.HTTPBasicCredentials = fastapi.Depends(security)):
  if credentials.username != "admin" or credentials.password != "admin":
    raise HTTPException(
      status_code = starlette.status.HTTP_401_UNAUTHORIZED,
      detail = "Incorrect email or password",
      headers = {"WWW-Authenticate": "Basic"},
    )
  else:
    return JSONResponse(app.openapi())

@app.get("/rest/docs", include_in_schema = False)
async def get_documentation(credentials: fastapi.security.HTTPBasicCredentials = fastapi.Depends(security)):
  if credentials.username != "admin" or credentials.password != "admin":
    raise HTTPException(
      status_code = starlette.status.HTTP_401_UNAUTHORIZED,
      detail = "Incorrect email or password",
      headers = {"WWW-Authenticate": "Basic"},
    )
  else:
    return fastapi.openapi.docs.get_swagger_ui_html(
      openapi_url = "/rest/docs/openapi.json",
      title = "docs",
      swagger_ui_parameters = { "defaultModelsExpandDepth": -1 }
      )
