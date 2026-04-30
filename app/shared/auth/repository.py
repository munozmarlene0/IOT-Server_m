from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import or_
from sqlmodel import Session, select

from app.database.model import (
    Administrator,
    Application,
    Device,
    Manager,
    SensitiveData,
    User,
)


HumanEntityType = Literal["administrator", "manager", "user"]


@dataclass
class ResolvedHumanAccount:
    account: Administrator | Manager | User
    sensitive_data: SensitiveData
    account_type: HumanEntityType
    is_master: bool


class AuthRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_human_by_email(
        self,
        *,
        email: str,
        entity_type: HumanEntityType,
    ) -> ResolvedHumanAccount | None:
        stmt = select(SensitiveData).where(SensitiveData.email == email)
        sensitive_data = self.session.exec(stmt).first()

        if sensitive_data is None:
            return None

        if entity_type == "administrator":
            account = sensitive_data.administrator
            is_master = bool(account.is_master) if account else False

        elif entity_type == "manager":
            account = sensitive_data.manager
            is_master = False

        elif entity_type == "user":
            account = sensitive_data.user
            is_master = False

        else:
            return None

        if account is None:
            return None

        return ResolvedHumanAccount(
            account=account,
            sensitive_data=sensitive_data,
            account_type=entity_type,
            is_master=is_master,
        )

    def get_device_by_identifier(self, identifier: str) -> Device | None:
        try:
            return self.session.get(Device, UUID(identifier))
        except ValueError:
            pass

        stmt = select(Device).where(
            or_(
                Device.name == identifier,
                Device.serial_number == identifier,
                Device.mac == identifier,
            )
        )
        return self.session.exec(stmt).first()

    def get_application_by_identifier(self, identifier: str) -> Application | None:
        try:
            return self.session.get(Application, UUID(identifier))
        except ValueError:
            pass

        stmt = select(Application).where(
            or_(
                Application.name == identifier,
                Application.api_key == identifier,
            )
        )
        return self.session.exec(stmt).first()

    def get_entity_for_xmss(
        self,
        *,
        entity_type: str,
        identifier: str,
    ):
        if entity_type in {"administrator", "manager", "user"}:
            human = self.get_human_by_email(
                email=identifier,
                entity_type=entity_type,
            )
            return human.account if human else None

        if entity_type == "device":
            return self.get_device_by_identifier(identifier)

        if entity_type == "application":
            return self.get_application_by_identifier(identifier)

        return None

    def get_human_for_xmss(
        self,
        *,
        entity_type: HumanEntityType,
        identifier: str,
    ) -> ResolvedHumanAccount | None:
        return self.get_human_by_email(
            email=identifier,
            entity_type=entity_type,
        )

    def get_xmss_state(self, entity) -> dict:
        return {
            "public_root": getattr(entity, "xmss_public_root", None),
            "current_index": getattr(entity, "xmss_current_index", 0) or 0,
            "tree_height": getattr(entity, "xmss_tree_height", 4) or 4,
        }

    def set_xmss_initial_state(
        self,
        *,
        entity,
        public_root: str,
        tree_height: int,
    ) -> None:
        entity.xmss_public_root = public_root
        entity.xmss_current_index = 0
        entity.xmss_tree_height = tree_height

        self.session.add(entity)
        self.session.commit()
        self.session.refresh(entity)

    def increment_xmss_index(self, entity) -> None:
        current_index = getattr(entity, "xmss_current_index", 0) or 0
        entity.xmss_current_index = current_index + 1

        self.session.add(entity)
        self.session.commit()
        self.session.refresh(entity)