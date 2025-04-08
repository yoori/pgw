import pydantic

class ErrorResponse(pydantic.BaseModel):
  status: int = 0,
  code: int = 0
  error: str = ''
