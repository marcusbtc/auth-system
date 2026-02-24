from datetime import UTC, datetime

from pymongo.database import Database

MIGRATIONS = []


def migration(version: str):
    def wrapper(fn):
        MIGRATIONS.append((version, fn))
        return fn

    return wrapper


@migration('2026_02_05_user_defaults')
def migration_user_defaults(db: Database) -> None:
    users = db['users']
    cursor = users.find({})
    for user in cursor:
        updates = {}
        if 'username_normalized' not in user and 'username' in user:
            updates['username_normalized'] = user['username'].strip().lower()
        if 'deleted_at' not in user:
            updates['deleted_at'] = None
        if 'created_at' not in user:
            updates['created_at'] = datetime.now(UTC)
        if 'updated_at' not in user:
            updates['updated_at'] = datetime.now(UTC)
        if 'last_login_at' not in user:
            updates['last_login_at'] = None
        if 'activation_expires_at' not in user:
            updates['activation_expires_at'] = None
        if 'reset_expires_at' not in user:
            updates['reset_expires_at'] = None
        if updates:
            users.update_one({'_id': user['_id']}, {'$set': updates})


def run_migrations(db: Database) -> list[str]:
    history = db['schema_migrations']
    applied = {row['version'] for row in history.find({}, {'version': 1})}
    executed: list[str] = []
    for version, fn in MIGRATIONS:
        if version in applied:
            continue
        fn(db)
        history.insert_one({'version': version, 'applied_at': datetime.now(UTC)})
        executed.append(version)
    return executed
