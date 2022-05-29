from dataclasses import dataclass
from typing import Callable

from sqlalchemy.orm import Session
from sqlalchemy.schema import Table
from sqlalchemy.sql import select
from sqlalchemy.dialects.postgresql import insert
import zope.interface

from ..interfaces import ISessionSerializer, IStorageShim


@zope.interface.implementer(IStorageShim)
@dataclass
class SqlalchemyStorageShim:
    """Store session dictionary serialized as json in db with SQLAlchemy."""

    db: Session
    table: Table
    serializer: ISessionSerializer

    mark_changed: Callable = None

    def store_session(self, session):
        session_dict = self.serializer.to_dict(session)
        values = dict(
            shop_name=session_dict["shop_name"],
            type=session_dict["type"],
            value=session_dict,
        )
        result = self.db.execute(
            insert(self.table)
            .values(id=session_dict["id"], **values)
            .on_conflict_do_update(index_elements=[self.table.c.id], set_=values)
        )
        if self.mark_changed:
            self.mark_changed(self.db)
        return result

    def load_session(self, session_id):
        row = (
            self.db.execute(select(self.table).where(self.table.c.id == session_id))
            .mappings()
            .first()
        )
        session_dict = self.serializer.from_dict(row["value"]) if row else None
        return session_dict

    def remove_session_by_id(self, session_id):
        return self.db.execute(self.table.delete().where(self.table.c.id == session_id))

    def remove_all_shop_sessions(self, shop_name):
        """Remove all sessions for this shop.

        This is intended to be used when shop uninstalls application.
        """
        return self.db.execute(
            self.table.delete().where(self.table.c.shop_name == shop_name)
        )
