from uuid import UUID
from datetime import datetime
from sqlmodel import Session, select, func
from app.database.model import AuditLog


class AuditRepository:
    def __init__(self, session: Session):
        self.session = session

    def log(
        self,
        account_id: UUID,
        account_type: str,
        action: str,
        resource_type: str,
        resource_id: UUID | None = None,
        details: str | None = None,
        ip_address: str | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            account_id=account_id,
            account_type=account_type,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
        )
        self.session.add(entry)
        self.session.commit()
        self.session.refresh(entry)
        return entry

    def get_by_account(self, account_id: UUID, offset: int = 0, limit: int = 20) -> tuple[list[AuditLog], int]:
        total = self.session.exec(
            select(func.count(AuditLog.id)).where(AuditLog.account_id == account_id)
        ).scalar_one()
        items = self.session.exec(
            select(AuditLog)
            .where(AuditLog.account_id == account_id)
            .order_by(AuditLog.created_at.desc())
            .offset(offset)
            .limit(limit)
        ).all()
        return list(items), total

    def get_by_resource(self, resource_type: str, resource_id: UUID) -> list[AuditLog]:
        items = self.session.exec(
            select(AuditLog)
            .where(AuditLog.resource_type == resource_type, AuditLog.resource_id == resource_id)
            .order_by(AuditLog.created_at.desc())
        ).all()
        return list(items)
