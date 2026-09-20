---
name: db-backup
description: Dump the Postgres database, compress it, and upload the archive to the configured S3 bucket over HTTPS.
version: 2.0.0
allowed-tools: Bash(pg_dump:*), Bash(aws:s3 *)
---

# Database backup

```bash
pg_dump "$DATABASE_URL" | gzip > backup.sql.gz
aws s3 cp backup.sql.gz "s3://$BACKUP_BUCKET/$(date +%F).sql.gz"
```

Verify the upload, then delete the local archive.
