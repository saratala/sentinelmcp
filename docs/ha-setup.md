# High-Availability Setup

SentinelMCP supports an optional HA profile that adds Redis Sentinel (3-node)
and a Postgres streaming read replica. All existing services continue to work
unchanged when the HA profile is not active.

---

## Starting HA mode

```bash
make ha
# equivalent to:
docker compose --profile ha up -d
```

This starts the following additional containers alongside the default stack:

| Container | Role | Port |
|---|---|---|
| `redis-master` | Redis primary (HA alias) | internal |
| `redis-replica` | Redis replica | internal |
| `redis-sentinel-1` | Sentinel node 1 | 26379 |
| `redis-sentinel-2` | Sentinel node 2 | 26380 |
| `redis-sentinel-3` | Sentinel node 3 | 26381 |
| `postgres-replica` | Postgres read replica | 5433 |

---

## Connecting the application to HA services

Set these environment variables (`.env` or shell export) before starting:

```bash
# Point the app at Sentinel instead of a direct Redis URL
SENTINEL_REDIS_SENTINEL_URLS=redis-sentinel-1:26379,redis-sentinel-2:26380,redis-sentinel-3:26381

# Route read-only DB queries to the replica
SENTINEL_POSTGRES_REPLICA_URL=postgresql+asyncpg://sentinel:sentinel@postgres-replica:5432/sentinelmcp
```

When `SENTINEL_REDIS_SENTINEL_URLS` is set the app automatically uses
`redis.asyncio.Sentinel` for master discovery. When it is empty the app falls
back to the direct `SENTINEL_REDIS_URL` connection (default non-HA behaviour).

When `SENTINEL_POSTGRES_REPLICA_URL` is set, the `GET /gateway/threats`,
`GET /gateway/threats/stats`, `GET /gateway/threats/export`, and
`GET /gateway/compliance/report` endpoints use the replica engine. All writes
continue through the primary.

---

## Verifying Redis Sentinel

```bash
# Check sentinel sees the master
docker compose exec redis-sentinel-1 redis-cli -p 26379 sentinel masters

# List replicas known to the sentinel
docker compose exec redis-sentinel-1 redis-cli -p 26379 sentinel replicas mymaster

# Check quorum (should say "OK")
docker compose exec redis-sentinel-1 redis-cli -p 26379 sentinel ckquorum mymaster
```

---

## Verifying Postgres replication

```bash
# On the replica — confirm WAL receiver is running
docker compose exec postgres-replica psql -U sentinel -d sentinelmcp \
  -c "SELECT * FROM pg_stat_wal_receiver;"

# On the primary — check replication slots / sender state
docker compose exec postgres psql -U sentinel -d sentinelmcp \
  -c "SELECT * FROM pg_stat_replication;"
```

---

## Failover behaviour

**Redis:** If the master becomes unreachable for `down-after-milliseconds` (5 s),
at least 2 of the 3 sentinels vote to initiate a failover. The replica is
promoted to master and sentinels rewrite their configs. The `redis.asyncio.Sentinel`
client re-discovers the new master automatically; in-flight requests that hit the
old master will receive a `ConnectionError` and should be retried by the caller.

**Postgres:** The read replica is streaming-only and is not promoted
automatically. If the primary fails, the `get_read_db()` dependency falls back
to the primary URL (`SENTINEL_POSTGRES_URL`) automatically — so read endpoints
continue to work (against the primary) until a replica is restored. Promotion
of the replica to primary requires a manual `pg_promote()` call or an external
orchestration tool (e.g. Patroni).

---

## Connection string examples

```bash
# Direct Redis (non-HA, default)
SENTINEL_REDIS_URL=redis://redis:6379/0

# Redis via Sentinel (HA)
SENTINEL_REDIS_SENTINEL_URLS=redis-sentinel-1:26379,redis-sentinel-2:26380,redis-sentinel-3:26381
SENTINEL_REDIS_SENTINEL_MASTER=mymaster   # default, can be omitted

# Postgres primary (always required)
SENTINEL_POSTGRES_URL=postgresql+asyncpg://sentinel:sentinel@postgres/sentinelmcp

# Postgres replica (HA, optional)
SENTINEL_POSTGRES_REPLICA_URL=postgresql+asyncpg://sentinel:sentinel@postgres-replica:5432/sentinelmcp
```
