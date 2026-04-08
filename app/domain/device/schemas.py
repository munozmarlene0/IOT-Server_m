from pydantic import BaseModel
from app.shared.base_domain.schemas import BaseSchemaResponse


class DeviceCreate(BaseModel):
    name: str
    brand: str
    model: str
    serial_number: str
    ip: str
    mac: str


class DeviceUpdate(BaseModel):
    name: str | None = None
    brand: str | None = None
    model: str | None = None
    serial_number: str | None = None
    ip: str | None = None
    mac: str | None = None
    is_active: bool | None = None


class DeviceResponse(BaseSchemaResponse):
    name: str
    brand: str
    model: str
    serial_number: str
    ip: str
    mac: str
    is_active: bool
