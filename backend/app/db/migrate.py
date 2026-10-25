"""Additive schema migration for existing SQLite databases.

``create_all`` creates missing tables but never alters existing ones, so a
database created by an earlier version would lack new nullable columns. This
adds them in place. Only nullable columns are added; nothing is dropped or
rewritten, so it is safe to run on every startup.
"""

from sqlalchemy import inspect, text


def upgrade(engine, metadata):
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table in metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing or not column.nullable:
                    continue
                kind = column.type.compile(dialect=engine.dialect)
                conn.execute(
                    text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {kind}')
                )
