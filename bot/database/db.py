#import aiosqlite
import asyncpg

#DB_PATH = "data/sentra_bot.db"
POSTGRES_DSN = "postgresql://postgres:3034390@localhost:5432/sentra"


class Database:
    def __init__(self, dsn=POSTGRES_DSN):
        self.dsn = dsn
        self.pool = None

    async def connect(self):
        self.pool = await asyncpg.create_pool(self.dsn)


    async def close(self):
        await self.pool.close()


    async def is_registered(self, chat_id: int) -> bool:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT 1 FROM users WHERE chat_id = $1", chat_id)
            return row is not None

    async def add_user(self, chat_id: int, first_name: str, username: str, language: str):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO users (chat_id, first_name, username, language)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (chat_id) DO NOTHING
            """, chat_id, first_name, username, language)

            await conn.execute("""
                INSERT INTO user_subscriptions (user_id, source_id)
                VALUES ($1, (SELECT id FROM sources WHERE source_name = 'NVD'))
                ON CONFLICT DO NOTHING
            """, chat_id)

    async def get_user_language(self, chat_id: int) -> str:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT language FROM users WHERE chat_id = $1", chat_id)
            return row["language"] if row else "en"

    async def set_user_language(self, chat_id: int, language: str):
        async with self.pool.acquire() as conn:
            await conn.execute("UPDATE users SET language = $1 WHERE chat_id = $2", language, chat_id)

    async def add_cve(self, bulletin_id: str, source_id: int, description: str, base_score: float, base_severity: str, published_date: str):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO cve (bulletin_id, source_id, description, base_score, base_severity, published_date)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (bulletin_id) DO NOTHING
            """, bulletin_id, source_id, description, base_score, base_severity, published_date)

    async def add_cpe(self, cve_id: str, cpe_uri: str):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO cpe (cve_id, cpe_uri)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
            """, cve_id, cpe_uri)

    async def get_cpe_by_cve_id(self, cve_id: str) -> list[str]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT cpe_uri FROM cpe WHERE cve_id = $1", cve_id)
            return [r["cpe_uri"] for r in rows]

    async def get_all_subscribed_users(self) -> list[int]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT DISTINCT users.chat_id
                FROM users
                JOIN user_subscriptions ON users.chat_id = user_subscriptions.user_id
                WHERE user_subscriptions.subscribed = TRUE
            """)
            return [r["chat_id"] for r in rows]

    async def get_all_sources(self) -> list[str]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT source_name FROM sources")
            return [r["source_name"] for r in rows]

    async def get_source_id_by_name(self, source_name: str):
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT id FROM sources WHERE source_name = $1", source_name)
            return row["id"] if row else None

    async def get_user_subscribed_sources(self, chat_id: int) -> list[str]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT s.source_name
                FROM user_subscriptions us
                JOIN users u ON us.user_id = u.chat_id
                JOIN sources s ON us.source_id = s.id
                WHERE u.chat_id = $1 AND us.subscribed = TRUE
            """, chat_id)
            return [r["source_name"] for r in rows]

    async def is_user_subscribed_to_source(self, chat_id: int, source_id: int) -> bool:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT subscribed FROM user_subscriptions
                WHERE user_id = $1 AND source_id = $2
            """, chat_id, source_id)
            return row and row["subscribed"] is True

    async def subscribe_user_to_source(self, chat_id: int, source_id: int):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO user_subscriptions (user_id, source_id, subscribed)
                VALUES ($1, $2, TRUE)
                ON CONFLICT (user_id, source_id) DO UPDATE SET subscribed = TRUE
            """, chat_id, source_id)

    async def unsubscribe_user_from_source(self, chat_id: int, source_id: int):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE user_subscriptions SET subscribed = FALSE
                WHERE user_id = $1 AND source_id = $2
            """, chat_id, source_id)

    async def check_bulletin_status(self, cve_id: str) -> bool:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT notified FROM cve WHERE bulletin_id = $1", cve_id)
            return bool(row["notified"]) if row else False

    async def update_bulletin_notified(self, cve_id: str):
        async with self.pool.acquire() as conn:
            await conn.execute("UPDATE cve SET notified = TRUE WHERE bulletin_id = $1", cve_id)

    async def search_cves(self, keyword: str) -> list[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM cve
                WHERE description ILIKE $1
                   OR bulletin_id ILIKE $1
                   OR base_severity ILIKE $1
                   OR published_date::TEXT ILIKE $1
                LIMIT 10
            """, f"%{keyword}%")
            return [dict(row) for row in rows]

    async def save_log_metadata(self, user_id: int, file_name: str):
        async with self.pool.acquire() as conn:
            await conn.execute("INSERT INTO logs (user_id, file_name) VALUES ($1, $2)", user_id, file_name)
