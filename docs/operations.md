# Production operations

## Release prerequisites

- Store `JWT_SECRET`, authenticated `MONGO_URI`, authenticated `REDIS_URL`, and
  their backing database credentials in the deployment platform; never commit
  them. URL-encode credentials embedded in connection URIs. Keep admin seeding
  disabled after bootstrap.
- Set `CORS_ALLOW_ORIGINS` and `TRUSTED_HOSTS` to the production domains.
- Use an immutable `APP_IMAGE` tag for every release and retain the previous
  known-good tag.
- Keep both `mongo-data` and `redis-data` on persistent storage. Do not expose
  MongoDB or Redis publicly.

## Backup and restore gate

Create and validate a backup before every schema-affecting release:

```bash
mkdir -p backups
docker compose exec -T mongo mongodump --db auth_system --archive > "backups/auth-system-$(date -u +%Y%m%dT%H%M%SZ).archive"
```

Test restores in an isolated environment first. Restoring replaces data and
must never be run as an automatic deployment step:

```bash
docker compose exec -T mongo mongorestore --drop --db auth_system --archive < backups/approved.archive
```

## Rollback

Set `APP_IMAGE` to the previous immutable image, then run
`docker compose up -d --no-build --wait api`. Verify `/api/system/health`,
`/api/system/ready`, login, refresh rotation, and logout revocation. A database
restore is a separate, explicitly approved operation.
