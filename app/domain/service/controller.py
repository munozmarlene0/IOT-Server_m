from app.shared.base_domain.controller import FullCrudApiController
from app.domain.service.schemas import ServiceCreate, ServiceResponse, ServiceUpdate
from app.domain.service.service import ServiceServiceDep
from app.shared.authorization.dependencies import require_read, require_write, require_delete  # nuevo
from app.database.model import Service  # nuevo


class ServiceController(FullCrudApiController):
    prefix = "/services"
    tags = ["Services"]
    service_dep = ServiceServiceDep
    response_schema = ServiceResponse
    create_schema = ServiceCreate
    update_schema = ServiceUpdate

    # nuevo
    list_dependencies = [require_read(Service)]
    retrieve_dependencies = [require_read(Service)]
    create_dependencies = [require_write(Service)]
    update_dependencies = [require_write(Service)]
    delete_dependencies = [require_delete(Service)]


service_router = ServiceController().router