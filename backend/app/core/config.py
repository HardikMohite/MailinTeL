import os
import secrets
import logging
from pathlib import Path
from typing import Optional, List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

logger = logging.getLogger("mailintel.config")

# Find root directory containing .env
BASE_DIR = Path(__file__).resolve().parent.parent.parent
ROOT_DIR = BASE_DIR.parent
ENV_PATH = ROOT_DIR / ".env" if (ROOT_DIR / ".env").exists() else BASE_DIR / ".env"

# Well-known insecure defaults — used ONLY to detect misconfiguration in non-dev
# environments. Includes every placeholder value that has shipped in this repo's
# .env / .env.example so a copy-pasted deliverable can't slip past the check
# (MVP-01 fix: the previous check only matched one literal string, so the
# actual placeholder committed in backend/.env — a 60+ char "CHANGE-ME..."
# string — was long enough to pass the old len(...) < 32 check unnoticed).
_INSECURE_DEFAULT_SECRET_KEY = "mailintel-development-secret-key-change-in-production"
_INSECURE_SECRET_KEY_MARKERS = ("change-me", "changeme", "change_me", "example", "insecure", "placeholder")


class Settings(BaseSettings):
    # App Settings
    APP_NAME: str = "MailinteL"
    APP_ENV: str = "development"
    DEBUG: bool = False  # SECURE DEFAULT: must be explicitly enabled for local dev
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = _INSECURE_DEFAULT_SECRET_KEY

    # Auth / JWT Settings
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_ALGORITHM: str = "HS256"
    BCRYPT_ROUNDS: int = 12
    # SECURE DEFAULT (MVP-06): closed unless explicitly opted into via .env — public
    # self-signup immediately grants a new organization admin, so it must be a
    # deliberate choice (e.g. a disposable demo), not something left on by omission.
    ALLOW_SELF_SIGNUP: bool = False
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # Server Settings
    BACKEND_HOST: str = "127.0.0.1"
    BACKEND_PORT: int = 8000
    PORT: Optional[int] = None
    FRONTEND_URL: str = "http://localhost:5173"
    # Comma-separated list of extra allowed CORS origins (beyond FRONTEND_URL / localhost dev defaults)
    ALLOWED_ORIGINS: str = ""
    # Regex pattern for allowed CORS origins (e.g. all Vercel preview domains: https://.*\.vercel\.app)
    CORS_ORIGIN_REGEX: Optional[str] = r"https://.*\.vercel\.app"

    @property
    def effective_port(self) -> int:
        return self.PORT or self.BACKEND_PORT

    @field_validator("APP_ENV")
    @classmethod
    def _normalize_env(cls, v: str) -> str:
        return (v or "development").strip().lower()

    @property
    def is_production(self) -> bool:
        return self.APP_ENV in ("production", "prod", "staging")

    @property
    def cors_origin_regex(self) -> Optional[str]:
        return self.CORS_ORIGIN_REGEX or None

    @property
    def cors_origins(self) -> List[str]:
        origins = {self.FRONTEND_URL, "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"}
        if self.ALLOWED_ORIGINS:
            for o in self.ALLOWED_ORIGINS.split(","):
                o = o.strip()
                if o:
                    origins.add(o)
        # In production, never fall back to permissive localhost dev origins
        if self.is_production:
            origins = {o for o in origins if "localhost" not in o and "127.0.0.1" not in o}
        return sorted([o for o in origins if o])

    # Database (PostgreSQL + pgvector / Supabase)
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "mailintel"
    POSTGRES_SSL: bool = False
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/mailintel"

    # Storage Configuration (Supports 'minio' or 'supabase')
    STORAGE_PROVIDER: str = "minio"  # "minio" or "supabase"

    # Supabase Storage Configuration
    SUPABASE_URL: Optional[str] = None
    SUPABASE_SERVICE_KEY: Optional[str] = None
    SUPABASE_KEY: Optional[str] = None

    # Universal Storage Buckets
    STORAGE_EVIDENCE_BUCKET: str = "mailintel-evidence"
    STORAGE_DERIVED_BUCKET: str = "mailintel-derived"
    STORAGE_REPORTS_BUCKET: str = "mailintel-reports"
    STORAGE_TEMP_BUCKET: str = "mailintel-temp"

    # MinIO
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_SECURE: bool = False
    MINIO_EVIDENCE_BUCKET: str = "mailintel-evidence"
    MINIO_DERIVED_BUCKET: str = "mailintel-derived"
    MINIO_REPORTS_BUCKET: str = "mailintel-reports"
    MINIO_TEMP_BUCKET: str = "mailintel-temp"

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None
    REDIS_SSL: bool = False
    REDIS_URL: str = "redis://localhost:6379/0"

    # Initial Administrator Account (Configured via .env)
    ADMIN_EMAIL: Optional[str] = "admin@mailintel.local"
    ADMIN_PASSWORD: Optional[str] = "ChangeMeAdmin123!"
    ADMIN_FULL_NAME: str = "Administrator"
    ADMIN_ORG_NAME: str = "MailIntel Security Operations"

    # Legacy Demo Context Defaults (Internal fallbacks, no longer in .env)
    DEMO_USER_ID: str = "00000000-0000-0000-0000-000000000001"
    DEMO_USER_EMAIL: str = "demo@mailintel.local"
    DEMO_USER_NAME: str = "MailIntel Demo User"
    DEMO_ORG_ID: str = "00000000-0000-0000-0000-000000000001"
    DEMO_ORG_NAME: str = "MailIntel Demo Organization"
    DEMO_ROLE: str = "Development Admin"

    # External Provider Keys & Intelligence Settings
    MAXMIND_GEOIP_DB_PATH: Optional[str] = None
    MAXMIND_LICENSE_KEY: Optional[str] = None
    MAXMIND_AUTO_DOWNLOAD: bool = True
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    IP_INTEL_CACHE_TTL_SECONDS: int = 86400
    ENABLE_LIVE_DNSBL_LOOKUPS: bool = False
    TOR_EXIT_LIST_URL: Optional[str] = "https://check.torproject.org/torbulkexitlist"

    # AI & RAG Intelligence Settings (Groq API + Forensic Fallback Engine)
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "openai/gpt-oss-120b"
    GROQ_FALLBACK_MODEL: str = "openai/gpt-oss-20b"
    GROQ_API_BASE: str = "https://api.groq.com/openai/v1"
    AI_TEMPERATURE: float = 0.1
    AI_MAX_TOKENS: int = 2048

    model_config = SettingsConfigDict(
        env_file=str(ENV_PATH),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def is_supabase_db(self) -> bool:
        """
        True when connecting to a Supabase-hosted PostgreSQL instance or pooler,
        or when POSTGRES_SSL is explicitly enabled.
        """
        host = (self.POSTGRES_HOST or "").lower()
        url = (self.DATABASE_URL or "").lower()
        return (
            "supabase.co" in host
            or "supabase.com" in host
            or "supabase.co" in url
            or "supabase.com" in url
            or "sslmode=require" in url
            or self.POSTGRES_SSL
        )

    @property
    def is_pooler_connection(self) -> bool:
        """
        Detects if connecting via Supabase transaction pooler (Supavisor / PgBouncer)
        either by port (6543), hostname ('pooler.supabase.com'), or URL query parameter.
        When True, prepared statement caching is disabled and NullPool is used.
        """
        url_lower = (self.DATABASE_URL or "").lower()
        host_lower = (self.POSTGRES_HOST or "").lower()
        return (
            self.POSTGRES_PORT == 6543
            or ":6543" in url_lower
            or "pooler.supabase.com" in host_lower
            or "pooler.supabase.com" in url_lower
            or "pgbouncer=true" in url_lower
        )

    @property
    def effective_database_url(self) -> str:
        """
        Returns the resolved database connection URL.
        Ensures the SQLAlchemy asyncpg driver scheme is present (e.g. converting
        postgresql:// to postgresql+asyncpg://) and dynamically assembles from
        POSTGRES_* fields if DATABASE_URL was left at default localhost while
        POSTGRES_HOST was changed to a remote endpoint.

        Safely cleans URL query parameters unsupported by asyncpg (such as
        sslmode, pgbouncer, connection_limit) that are commonly present in URLs
        copied directly from the Supabase Dashboard.
        """
        raw_url = (self.DATABASE_URL or "").strip()
        host_changed = self.POSTGRES_HOST not in ("localhost", "127.0.0.1", "::1")
        url_is_default = raw_url in (
            "postgresql+asyncpg://postgres:postgres@localhost:5432/mailintel",
            "postgresql://postgres:postgres@localhost:5432/mailintel",
            "",
            None,
        )

        if (host_changed and url_is_default) or not raw_url:
            url_obj = URL.create(
                drivername="postgresql+asyncpg",
                username=self.POSTGRES_USER,
                password=self.POSTGRES_PASSWORD,
                host=self.POSTGRES_HOST,
                port=self.POSTGRES_PORT,
                database=self.POSTGRES_DB,
            )
            return url_obj.render_as_string(hide_password=False)

        # Normalize driver scheme for asyncpg
        if raw_url.startswith("postgresql://"):
            raw_url = "postgresql+asyncpg://" + raw_url[len("postgresql://"):]
        elif raw_url.startswith("postgres://"):
            raw_url = "postgresql+asyncpg://" + raw_url[len("postgres://"):]

        # Clean query parameters unsupported by asyncpg (e.g. from Supabase dashboard copy-paste)
        try:
            url_parsed = make_url(raw_url)
            query_params = dict(url_parsed.query)
            changed = False
            for param in ("sslmode", "pgbouncer", "connection_limit", "pool_timeout"):
                if param in query_params:
                    query_params.pop(param)
                    changed = True
            if changed or not url_parsed.drivername.startswith("postgresql+asyncpg"):
                url_parsed = url_parsed.set(drivername="postgresql+asyncpg", query=query_params)
                return url_parsed.render_as_string(hide_password=False)
        except Exception:
            pass

        return raw_url

    @property
    def active_storage_provider(self) -> str:
        """
        Determines the active storage provider ('supabase' or 'minio').
        If STORAGE_PROVIDER is explicitly set to 'supabase', or if SUPABASE_URL
        is provided while STORAGE_PROVIDER is at default 'minio', returns 'supabase'.
        """
        provider = (self.STORAGE_PROVIDER or "").lower().strip()
        if provider == "supabase" or (provider == "minio" and bool(self.SUPABASE_URL)):
            return "supabase"
        return "minio"

    @property
    def effective_supabase_key(self) -> Optional[str]:
        return self.SUPABASE_SERVICE_KEY or self.SUPABASE_KEY

    @property
    def evidence_bucket(self) -> str:
        return self.STORAGE_EVIDENCE_BUCKET or self.MINIO_EVIDENCE_BUCKET

    @property
    def derived_bucket(self) -> str:
        return self.STORAGE_DERIVED_BUCKET or self.MINIO_DERIVED_BUCKET

    @property
    def reports_bucket(self) -> str:
        return self.STORAGE_REPORTS_BUCKET or self.MINIO_REPORTS_BUCKET

    @property
    def temp_bucket(self) -> str:
        return self.STORAGE_TEMP_BUCKET or self.MINIO_TEMP_BUCKET

    @property
    def resolved_maxmind_paths(self) -> List[Path]:
        """
        Discovers and returns all valid existing MaxMind .mmdb file paths.
        Supports:
        - Absolute path (e.g. C:\\Dev\\MailinTeL\\data\\GeoLite2-ASN.mmdb or /app/data/GeoLite2-ASN.mmdb)
        - Relative path from project root (e.g. data/GeoLite2-ASN.mmdb)
        - Directory containing .mmdb files (e.g. data/ or /app/data)
        - Auto-discovery in standard data/ folders
        """
        paths: List[Path] = []
        candidates: List[Path] = []

        if self.MAXMIND_GEOIP_DB_PATH:
            raw_p = Path(self.MAXMIND_GEOIP_DB_PATH.strip())
            candidates.extend([raw_p, ROOT_DIR / raw_p, BASE_DIR / raw_p])

        # Standard fallback search locations
        candidates.extend([
            ROOT_DIR / "data",
            BASE_DIR / "data",
            ROOT_DIR / "data" / "GeoLite2-ASN.mmdb",
            ROOT_DIR / "data" / "GeoLite2-City.mmdb",
            BASE_DIR / "data" / "GeoLite2-ASN.mmdb",
            BASE_DIR / "data" / "GeoLite2-City.mmdb",
        ])

        seen = set()
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                if resolved.is_file() and resolved.suffix == ".mmdb":
                    paths.append(resolved)
                elif resolved.is_dir():
                    for mmdb_file in resolved.glob("*.mmdb"):
                        r_file = mmdb_file.resolve()
                        if r_file not in seen:
                            seen.add(r_file)
                            paths.append(r_file)
            except Exception:
                continue

        return paths

    @property
    def _network_reachable(self) -> bool:
        """
        True when the server is bound to listen beyond localhost (e.g. 0.0.0.0
        or a specific non-loopback interface), regardless of what APP_ENV says.
        A misconfigured APP_ENV should not be the only thing standing between
        an operator and shipping dev secrets to a reachable service.
        """
        return self.BACKEND_HOST not in ("127.0.0.1", "localhost", "::1")

    def validate_production_safety(self) -> None:
        """
        Fail fast (rather than silently running insecurely) if a production/staging
        deployment, OR any deployment reachable beyond localhost, still has
        development-grade settings. This is the single most common cause of
        real-world breaches: shipping dev defaults to prod.
        """
        secret_key_weak = (
            self.SECRET_KEY == _INSECURE_DEFAULT_SECRET_KEY
            or len(self.SECRET_KEY) < 32
            or any(marker in self.SECRET_KEY.lower() for marker in _INSECURE_SECRET_KEY_MARKERS)
        )

        problems = []
        if secret_key_weak:
            problems.append(
                "SECRET_KEY is missing/default/placeholder/too short. Generate one with: "
                "python -c \"import secrets; print(secrets.token_urlsafe(64))\""
            )
        if self.DEBUG:
            problems.append("DEBUG must be False.")
        # Check database password safety
        db_password_weak = False
        raw_db_url = (self.DATABASE_URL or "").strip()
        is_default_localhost_db = raw_db_url in (
            "postgresql+asyncpg://postgres:postgres@localhost:5432/mailintel",
            "postgresql://postgres:postgres@localhost:5432/mailintel",
            "",
            None,
        )

        if not is_default_localhost_db:
            try:
                parsed_url = make_url(self.effective_database_url)
                if parsed_url.password in ("postgres", "", None):
                    db_password_weak = True
            except Exception:
                pass
        else:
            if self.POSTGRES_PASSWORD in ("postgres", ""):
                db_password_weak = True

        if db_password_weak:
            problems.append("POSTGRES_PASSWORD (or DATABASE_URL password) is using an insecure default ('postgres' or empty).")

        if self.active_storage_provider == "supabase":
            if not self.SUPABASE_URL or not (
                self.SUPABASE_URL.startswith("https://") or self.SUPABASE_URL.startswith("http://")
            ):
                problems.append("SUPABASE_URL must be configured with a valid HTTP(S) URL when using Supabase storage.")
            if not self.effective_supabase_key or len(self.effective_supabase_key) < 10:
                problems.append("SUPABASE_SERVICE_KEY (or SUPABASE_KEY) must be provided when using Supabase storage.")
        else:
            if self.MINIO_ACCESS_KEY == "minioadmin" or self.MINIO_SECRET_KEY == "minioadmin":
                problems.append("MINIO_ACCESS_KEY/MINIO_SECRET_KEY are still MinIO defaults.")

        if problems:
            message = "Refusing to start in an insecure configuration:\n- " + "\n- ".join(problems)
            # Hard-fail whenever APP_ENV says production/staging, AND whenever the
            # server is bound to listen beyond localhost while APP_ENV was left at
            # its default ("development") — the combination most likely to mean an
            # operator copied dev defaults into a reachable deployment without also
            # remembering to flip APP_ENV. A deliberately-labelled local dev/staging
            # environment can still opt out of the hard-fail by setting APP_ENV to
            # something other than "development" is NOT required; instead, local
            # dev workflows should bind BACKEND_HOST to 127.0.0.1/localhost.
            if self.is_production or (self._network_reachable and self.APP_ENV == "development"):
                raise RuntimeError(message)
            logger.warning(message)


settings = Settings()
