import typing
import typing_extensions
import fastapi
import pydantic

import dpi_swagger.utils


router = fastapi.APIRouter(
  prefix = "/api",
  tags = [ "public" ],
)

class SessionKey(pydantic.BaseModel):
  traffic_type: str = pydantic.Field(description='Протокол')
  category_type: str = pydantic.Field(description='Категория траффика')


@router.post("/set_user_shaping",
  status_code = 204,
  responses = {
    fastapi.status.HTTP_400_BAD_REQUEST: {
      'model': dpi_swagger.utils.ErrorResponse,
      'description': 'Validation error'
    }
  },
  tags = ['public'])
async def Set_user_shaping(
  msisdn: typing_extensions.Annotated[
    str,
    fastapi.Query(description = 'Значение msisdn')
    ],
  sessions : typing_extensions.Annotated[
    typing.List[SessionKey],
    fastapi.Body(description = 'Массив ключей определяющих типы траффика к которым нужно применить ограничение', embed = True)
  ],
  bps : typing_extensions.Annotated[
    str,
    fastapi.Body(description = 'bytes per second ограничение для суммарного траффика по типам указанным в sessions', embed = True)
  ],
  ):
  return fastapi.Response(status_code = 204)
