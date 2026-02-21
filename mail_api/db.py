import os
import sqlite3
from contextlib import contextmanager


def _db_path() -> str:
    base_dir = os.environ.get("MAIL_API_DATA_DIR")
    if not base_dir:
        base_dir = os.path.join(os.getcwd(), "data")
    os.makedirs(base_dir, exist_ok=True)
    return os.path.join(base_dir, "mail_api.db")


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            create table if not exists settings (
                key text primary key,
                value text not null
            )
            """
        )

        conn.execute(
            """
            create table if not exists webhooks (
                id integer primary key autoincrement,
                name text not null,
                relay_key text not null unique,
                is_active integer not null default 1,
                sender_email text not null,
                webhook_secret text not null,
                timestamp_skew_seconds integer not null default 300,
                allow_from_override integer not null default 0,
                smtp_host text not null default '',
                smtp_port text not null default '587',
                smtp_security text not null default 'starttls',
                smtp_username text not null default '',
                smtp_password text not null default '',
                smtp_timeout_seconds text not null default '15',
                smtp_ignore_certificates text not null default '0',
                smtp_sender_name text not null default '',
                smtp_envelope_from_override text not null default '',
                relay_scenario text not null default 'smtp',
                imap_host text not null default '',
                imap_port text not null default '993',
                imap_security text not null default 'ssl',
                imap_username text not null default '',
                imap_password text not null default '',
                pop3_host text not null default '',
                pop3_port text not null default '995',
                pop3_security text not null default 'ssl',
                pop3_username text not null default '',
                pop3_password text not null default '',
                created_at text not null,
                updated_at text not null
            )
            """
        )

        webhook_cols = {
            str(r["name"])
            for r in conn.execute(
                "pragma table_info(webhooks)"
            ).fetchall()
        }
        if "smtp_envelope_from_override" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "smtp_envelope_from_override text not null default ''"
            )
        if "relay_scenario" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "relay_scenario text not null default 'smtp'"
            )
        if "imap_host" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "imap_host text not null default ''"
            )
        if "imap_port" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "imap_port text not null default '993'"
            )
        if "imap_security" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "imap_security text not null default 'ssl'"
            )
        if "imap_username" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "imap_username text not null default ''"
            )
        if "imap_password" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "imap_password text not null default ''"
            )
        if "pop3_host" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "pop3_host text not null default ''"
            )
        if "pop3_port" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "pop3_port text not null default '995'"
            )
        if "pop3_security" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "pop3_security text not null default 'ssl'"
            )
        if "pop3_username" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "pop3_username text not null default ''"
            )
        if "pop3_password" not in webhook_cols:
            conn.execute(
                "alter table webhooks add column "
                "pop3_password text not null default ''"
            )
        conn.execute(
            """
            create table if not exists outbound_queue (
                id integer primary key autoincrement,
                created_at text not null,
                updated_at text not null,
                status text not null,
                webhook_id integer not null default 0,
                to_addr text not null,
                from_addr text not null,
                subject text not null,
                body_text text not null,
                message_bytes blob not null,
                attempts integer not null default 0,
                next_attempt_at text not null,
                last_error text not null
            )
            """
        )

        cols = {
            str(r["name"])
            for r in conn.execute(
                "pragma table_info(outbound_queue)"
            ).fetchall()
        }
        if "webhook_id" not in cols:
            conn.execute(
                "alter table outbound_queue "
                "add column webhook_id integer not null default 0"
            )
        conn.execute(
            """
            create table if not exists admin_users (
                id integer primary key autoincrement,
                username text not null unique,
                password_hash text not null,
                is_active integer not null default 1,
                created_at text not null
            )
            """
        )
        conn.execute(
            """
            create table if not exists ip_rules (
                id integer primary key autoincrement,
                action text not null,
                cidr text not null,
                created_at text not null
            )
            """
        )
        conn.execute(
            """
            create table if not exists webhook_ip_rules (
                id integer primary key autoincrement,
                webhook_id integer not null,
                action text not null,
                cidr text not null,
                created_at text not null
            )
            """
        )
        conn.execute(
            """
            create table if not exists audit_log (
                id integer primary key autoincrement,
                actor text not null,
                action text not null,
                details text not null,
                created_at text not null
            )
            """
        )
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(_db_path())
    try:
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        conn.close()
