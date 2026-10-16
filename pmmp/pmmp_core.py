# PMMP BBS core

import os
import sqlite3
import base64
from datetime import datetime
from typing import Any, Optional
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519

## SQL
class db:
    """Single entry point for every SQL request.

    Generic helpers: insert, select, update, delete.
    Dedicated methods: <table>_insert and user_get_all_with_peer.
    """

    def __init__(self, db_path: str = "pmmp.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def close(self):
        self.conn.close()

    # ---- generic helpers ----
    def insert(self, table: str, values: dict[str, Any]) -> bool:
        columns = ", ".join(values)
        placeholders = ", ".join("?" for _ in values)
        try:
            with self.conn:
                self.conn.execute(
                    f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",
                    tuple(values.values()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def select(self, table: str, column: str, value: Any = None) -> Any:
        # value None -> all rows (fetchall), otherwise a single row (fetchone)
        try:
            with self.conn:
                cursor = self.conn.cursor()
                if value is None:
                    cursor.execute(f"SELECT * FROM {table}")
                    return cursor.fetchall()
                cursor.execute(f"SELECT * FROM {table} WHERE {column} = ?", (value,))
                return cursor.fetchone()
        except sqlite3.Error:
            return None

    def delete(self, table: str, row_id: int) -> bool:
        try:
            with self.conn:
                self.conn.execute(f"DELETE FROM {table} WHERE id = ?", (row_id,))
            return True
        except sqlite3.Error:
            return False

    def update(self, table: str, column: str, row_id: int, value: Any) -> bool:
        try:
            with self.conn:
                self.conn.execute(f"UPDATE {table} SET {column} = ? WHERE id = ?", (value, row_id))
            return True
        except sqlite3.Error:
            return False

    # ---- tables ----
    def _init_db(self):
        with self.conn:
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                registered BOOLEAN DEFAULT TRUE,
                key_priv TEXT NOT NULL,
                key_pub TEXT NOT NULL,
                password TEXT NOT NULL,
                callsign TEXT,
                meshtastic_id TEXT,
                email TEXT,
                last_con DATETIME,
                pin INTEGER,
                peer_id INTEGER
            )
            """)
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                ip TEXT,
                key_pub TEXT,
                trust_lvl INTEGER,
                status BOOLEAN
            )
            """)
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                channel_type INTEGER,
                key_pub TEXT,
                owner_id INTEGER,
                peer_id INTEGER,
                last_msg_id INTEGER,
                retention INTEGER
            )
            """)
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS channel_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type INTEGER
            )
            """)
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER,
                sender TEXT,
                title TEXT,
                content TEXT,
                read BOOLEAN,
                date DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """)
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS channel_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER,
                user_id INTEGER,
                access_level INTEGER,
                last_view INTEGER
            )
            """)
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS channel_sync (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER,
                peer_id INTEGER,
                allowed BOOLEAN
            )
            """)

    # ---- dedicated requests ----
    ## var after * should be named when call
    def set_user(self, name: str, registered: int, key_priv: str, key_pub: str, password: str, *, 
                    callsign: Optional[str] = None, 
                    meshtastic_id: Optional[str] = None, 
                    email: Optional[str] = None, 
                    pin: Optional[int] = None, 
                    peer_id: Optional[int] = 0, 
                    last_con: Optional[datetime] = None):
        return self.insert("users", {
            "name": name, "registered": registered, "key_priv": key_priv, "key_pub": key_pub,
            "password": password, "callsign": callsign, "meshtastic_id": meshtastic_id,
            "email": email, "pin": pin, "peer_id": peer_id, "last_con": last_con,
        })

    def get_user(self, *,
                 user_name: Optional[str] = None,
                 user_id: Optional[int] = None,
                 peer_id: Optional[int] = None,
                 detail: Optional[bool] = False):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.row_factory = sqlite3.Row
                if detail:
                    RequestArg="*"
                else:
                    RequestArg="users.id, users.name, users.key_pub, users.callsign, users.meshtastic_id, users.email, users.last_con, users.peer_id"
                filters: dict[str, Any] = {"name": user_name, "id": user_id, "peer_id": peer_id}
                conditions: list[str] = [f"{col} = ?" for col, val in filters.items() if val is not None]
                params: list[Any] = [val for val in filters.values() if val is not None]
                query = "SELECT " + RequestArg + " FROM users"
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                cursor.execute(query, params)
                return cursor.fetchone()
        except sqlite3.Error:
            return None

    def get_linked_user_peer(self, *,
                             user_id: Optional[int] = None,
                             peer_id: Optional[int] = None,
                             detail: Optional[bool] = False):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.row_factory = sqlite3.Row
                if detail:
                    RequestArg="users.id, users.name, users.key_pub, users.callsign, users.meshtastic_id, users.email, users.last_con, peers.id AS linked_peer_id, peers.name AS peer_name, peers.ip AS peer_ip, peers.key_pub AS peer_key_pub, peers.trust_lvl AS peer_trust_lvl, peers.status AS peer_status"
                else:
                    RequestArg="users.id, users.name, users.key_pub, peers.id AS linked_peer_id, peers.name AS peer_name, peers.ip AS peer_ip, peers.key_pub AS peer_key_pub, peers.trust_lvl AS peer_trust_lvl, peers.status AS peer_status"
                if user_id is None:
                    if peer_id is not None:
                        cursor.execute("""
                        SELECT """ + RequestArg + """
                        FROM users
                        LEFT JOIN peers ON users.peer_id = peers.id
                        WHERE peers.id = ? 
                        ORDER BY users.id
                        """, (peer_id,))
                    else:
                        cursor.execute("""
                        SELECT """ + RequestArg + """
                        FROM users
                        LEFT JOIN peers ON users.peer_id = peers.id
                        ORDER BY users.id
                        """)
                elif peer_id is not None:
                    cursor.execute("""
                    SELECT """ + RequestArg + """
                    FROM users
                    LEFT JOIN peers ON users.peer_id = peers.id
                    WHERE users.id = ? AND peers.id = ?
                    ORDER BY users.id
                    """, (user_id, peer_id))
                else:
                    cursor.execute("""
                    SELECT """ + RequestArg + """
                    FROM users
                    LEFT JOIN peers ON users.peer_id = peers.id
                    WHERE users.id = ?
                    ORDER BY users.id
                    """, (user_id,))
                return cursor.fetchall()
        except sqlite3.Error:
            return None

    def set_peer(self, name: str, ip: Optional[str] = None, key_pub: Optional[str] = None, trust_lvl: Optional[int] = None, status: Optional[bool] = None):
        return self.insert("peers", {
            "name": name, "ip": ip, "key_pub": key_pub, "trust_lvl": trust_lvl, "status": status,
        })

    def set_channel(self, name: str, channel_type: Optional[int] = 0, key_pub: Optional[str] = None, owner_id: Optional[int] = 0, peer_id: Optional[int] = None, last_msg_id: Optional[int] = None, retention: Optional[int] = None):
        return self.insert("channels", {
            "name": name, "channel_type": channel_type, "key_pub": key_pub, "owner_id": owner_id,
            "peer_id": peer_id, "last_msg_id": last_msg_id, "retention": retention,
        })

    def get_channel(self, *,
                    channel_id: Optional[int] = None,
                    channel_name: Optional[str] = None,
                    channel_type: Optional[int] = None,
                    owner_id: Optional[int] = None,
                    peer_id: Optional[int] = None):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.row_factory = sqlite3.Row
                if channel_name is not None:
                    cursor.execute("""
                    SELECT *
                    FROM channels
                    WHERE name = ?
                    ORDER BY id
                    """, (channel_name,))
                if channel_id is not None:
                    if channel_type is not None:
                        if owner_id is not None:
                            if peer_id is not None:
                                cursor.execute("""
                                SELECT *
                                FROM channels
                                WHERE id = ? AND channel_type = ? AND owner_id = ? AND peer_id = ?
                                ORDER BY id
                                """, (channel_id, channel_type, owner_id, peer_id))
                            else:
                                cursor.execute("""
                                SELECT *
                                FROM channels
                                WHERE id = ? AND channel_type = ? AND owner_id = ?
                                ORDER BY id
                                """, (channel_id, channel_type, owner_id))
                        else:
                            cursor.execute("""
                            SELECT *
                            FROM channels
                            WHERE id = ? AND channel_type = ?
                            ORDER BY id
                            """, (channel_id, channel_type))
                    else:
                        cursor.execute("""
                        SELECT *
                        FROM channels
                        WHERE id = ?
                        ORDER BY id
                        """, (channel_id,))
                else:
                    cursor.execute("""
                    SELECT *
                    FROM channels
                    ORDER BY id
                    """)
                return cursor.fetchall()

        except sqlite3.Error:
            return None

    def set_channel_type(self, type: Optional[int] = None):
        return self.insert("channel_types", {"type": type})

    def get_channel_type(self, *,
                id: Optional[int] = None,
                name: Optional[str] = None): 
        try:
            with self.conn:
                cursor = self.conn.cursor()
                if id is not None:
                    cursor.execute("""
                    SELECT *
                    FROM channel_types
                    WHERE id = ?
                    ORDER BY id
                    """, (id,))
                elif name is not None:
                    cursor.execute("""
                    SELECT *
                    FROM channel_types
                    WHERE name = ?
                    ORDER BY id
                    """, (name,))
                else:
                    cursor.execute("""
                    SELECT *
                    FROM channel_types
                    ORDER BY id
                    """)
                return cursor.fetchall()
        except sqlite3.Error:
            return None

    def set_message(self, channel_id: Optional[int] = None, sender: Optional[str] = None, title: Optional[str] = None, content: Optional[str] = None, read: Optional[bool] = None, date: Optional[datetime] = None):
        values: dict[str, Any] = {"channel_id": channel_id, "sender": sender, "title": title, "content": content, "read": read}
        if date is not None:
            values["date"] = date
        return self.insert("messages", values)

    def get_message(self, *,
                id: Optional[int] = None,
                channel_id: Optional[int] = None,
                sender: Optional[str] = None,
                title: Optional[str] = None,
                content: Optional[str] = None):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                if id is not None:
                    cursor.execute("""
                    SELECT *
                    FROM messages
                    WHERE id = ?
                    ORDER BY id
                    """, (id,))
                elif channel_id is not None:
                    cursor.execute("""
                    SELECT *
                    FROM messages
                    WHERE channel_id = ?
                    ORDER BY id
                    """, (channel_id,))
                elif sender is not None:
                    cursor.execute("""
                    SELECT *
                    FROM messages
                    WHERE sender = ?
                    ORDER BY id
                    """, (sender,))
                elif title is not None:
                    cursor.execute("""
                    SELECT *
                    FROM messages
                    WHERE title = ?
                    ORDER BY id
                    """, (title,))
                else:
                    cursor.execute("""
                    SELECT *
                    FROM messages
                    ORDER BY id
                    """)
                return cursor.fetchall()
        except sqlite3.Error:
            return None

    def get_mailbox(self, user_id: int, 
                    peer_id: Optional[int] = None):
        # messages -> channels (channel_id) -> users (owner_id) -> peers (users.peer_id)
        try:
            with self.conn:
                cursor = self.conn.cursor()
                if peer_id is None:
                    peer_id = 0
                cursor.execute(
                    """
                    SELECT messages.*
                    FROM messages
                    JOIN channels ON messages.channel_id = channels.id
                    JOIN users ON channels.owner_id = users.id
                    LEFT JOIN peers ON users.peer_id = peers.id
                    WHERE channels.channel_type = 0 AND users.id = ? AND peers.id = ?
                    """, (user_id, peer_id))
                return cursor.fetchall()
        except sqlite3.Error:
            return None

    def set_channel_access(self, channel_id: Optional[int] = None, user_id: Optional[int] = None, access_level: Optional[int] = None, last_view: Optional[int] = None):
        return self.insert("channel_access", {
            "channel_id": channel_id, "user_id": user_id,
            "access_level": access_level, "last_view": last_view,
        })

    def set_channel_sync(self, channel_id: Optional[int] = None, peer_id: Optional[int] = None, allowed: Optional[bool] = None):
        return self.insert("channel_sync", {"channel_id": channel_id, "peer_id": peer_id, "allowed": allowed})


class pmmpcore:
    def __init__(self, db: db):
        self._db = db

    def create_user(self, username: str, password: str, *, 
                    callsign: Optional[str] = None, 
                    meshtastic_id: Optional[str] = None, 
                    email: Optional[str] = None):
        ## Error code : 
        # 0 : OK
        # 1 : Username already exists
        # 2 : Password does not meet security requirements
        # 3 : Failed to create user

        ## Check that username do not exist on the local peer
        try:
            existing_user = self._db.get_user(user_name=username)
        except sqlite3.Error:
            return 1
        if existing_user is not None:
            return 1
        
        ## Check that the password meets security requirements
        if not password or len(password) < 8:
            return 2
        if not any(c.isupper() for c in password):
            return 2
        if not any(c.islower() for c in password):
            return 2
        if not any(c.isdigit() for c in password):
            return 2
        if not any(c in "!@#$%^&*()-_=+[{]}\|;:'\",<.>/?`~" for c in password):
            return 2
        

        ## Generate the keys
        encrypted_priv_b64, key_pub_b64 = crypto.generate_encrypted_key_pair(password)

        ## Store the user in the database
        self._db.set_user(username, True, encrypted_priv_b64, key_pub_b64, password, callsign=callsign, meshtastic_id=meshtastic_id, email=email, pin=None, peer_id=0, last_con=None)

        new_user = self._db.get_user(user_name=username)
        if new_user is None:
            return 3

        ## Create local folder for the user
        os.makedirs(f"./users/{new_user['id']}", exist_ok=True)
        
        return 0


class crypto:
    @staticmethod
    def encrypt_private_key(raw_priv: bytes, password: str) -> str:
        salt = os.urandom(16)
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=2,
            memory_cost=65536,  # 64 MiB
            lanes=4
        )
        derived_key = kdf.derive(password.encode('utf-8'))
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        encrypted_priv = aesgcm.encrypt(nonce, raw_priv, None)
        return base64.b64encode(encrypted_priv).decode('utf-8')

    @staticmethod
    def decrypt_private_key(encrypted_priv_b64: str, password: str) -> bytes:
        encrypted_priv = base64.b64decode(encrypted_priv_b64)
        salt = os.urandom(16)
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=2,
            memory_cost=65536,  # 64 MiB
            lanes=4
        )
        derived_key = kdf.derive(password.encode('utf-8'))
        aesgcm = AESGCM(derived_key)
        nonce = encrypted_priv[:12]
        ciphertext = encrypted_priv[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    @staticmethod
    def generate_key_pair() -> tuple[bytes, bytes]:
        key_priv = x25519.X25519PrivateKey.generate()
        key_pub = key_priv.public_key()
        raw_priv = key_priv.private_bytes_raw()
        raw_pub = key_pub.public_bytes_raw()
        return raw_priv, raw_pub

    @staticmethod
    def generate_encrypted_key_pair(password: str) -> tuple[str, str]:
        raw_priv, raw_pub = crypto.generate_key_pair()
        pub_b64 = base64.b64encode(raw_pub).decode('utf-8')
        encrypted_priv_b64 = crypto.encrypt_private_key(raw_priv, password)
        return encrypted_priv_b64, pub_b64