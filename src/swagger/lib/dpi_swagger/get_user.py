import typing
import typing_extensions
import fastapi
import pydantic

import dpi_swagger.utils


router = fastapi.APIRouter(
  prefix = "/api",
  tags = [ "public" ],
)

class UserAmount(pydantic.BaseModel):
  traffic_type: str = pydantic.Field(description='Протокол')
  category: str = pydantic.Field(description='Категория траффика')
  packets: int = pydantic.Field(description='Количество сетевых пакетов')
  size: int = pydantic.Field(description='Потребленный траффик (в байтах)')

class UserBlockedSession(pydantic.BaseModel):
  traffic_type: str = pydantic.Field(description='Протокол')
  category: str = pydantic.Field(description='Категория траффика')
  block_timestamp: str = pydantic.Field(description='Время до которого заблокированны сессии')

class UserClosedSession(pydantic.BaseModel):
  traffic_type: str = pydantic.Field(description='Протокол')
  category: str = pydantic.Field(description='Категория траффика')
  first_packet_timestamp: str = pydantic.Field(description='Время начала сессии')
  first_packet_timestamp: str = pydantic.Field(description='Время окончания сессии')

class GetUserResponse(pydantic.BaseModel):
  msisdn: str = pydantic.Field(description='Запрошенный msisdn')
  ip: typing.Optional[str] = pydantic.Field(description='Текущий назначенный пользователю IP')
  amounts: typing.List[UserAmount] = pydantic.Field(description='Потребленный траффик пользователя по типам траффика, расчитанный с запуска сервиса')
  blocked_sessions: typing.List[UserBlockedSession] = pydantic.Field(description='Заблокированные сессии для пользователя')
  closed_sessions: typing.List[UserClosedSession] = pydantic.Field(description='Завершенные сессии пользователя')

@router.get("/get_user",
  response_model = typing.Union[GetUserResponse],
  responses = {
    fastapi.status.HTTP_400_BAD_REQUEST: {
      'model': dpi_swagger.utils.ErrorResponse,
      'description': 'Validation error'
    }
  },
  tags = ['public'])
async def Get_user_information(
  msisdn: typing_extensions.Annotated[
    str,
    fastapi.Query(description = 'Значение msisdn')
    ]
  ):
  return fastapi.Response(status_code = 204)
