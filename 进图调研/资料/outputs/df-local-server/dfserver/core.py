from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sqlite3
import time
import unicodedata
import uuid


class DomainError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def fail(code, message):
    raise DomainError(code, message)


def text_value(value, name, maximum=128):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        fail("INVALID_ARGUMENT", f"{name} must be a nonempty string of at most {maximum} characters")
    return value


def integer(value, name, minimum=0, maximum=2**31-1):
    if type(value) is not int or not minimum <= value <= maximum:
        fail("INVALID_ARGUMENT", f"{name} must be an integer between {minimum} and {maximum}")
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


SCHEMA = """
CREATE TABLE IF NOT EXISTS players (
 id TEXT PRIMARY KEY, local_name TEXT NOT NULL UNIQUE, revision INTEGER NOT NULL DEFAULT 0,
 money INTEGER NOT NULL DEFAULT 0 CHECK(money>=0), xp INTEGER NOT NULL DEFAULT 0 CHECK(xp>=0));
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, player_id TEXT NOT NULL REFERENCES players(id), expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS accounts (
 username_key TEXT PRIMARY KEY, player_id TEXT NOT NULL UNIQUE REFERENCES players(id),
 password_salt BLOB NOT NULL, password_verifier BLOB NOT NULL, password_iterations INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS native_identities (
 player_id TEXT PRIMARY KEY REFERENCES players(id),
 native_id INTEGER NOT NULL UNIQUE CHECK(native_id>0));
CREATE TABLE IF NOT EXISTS game_profiles (
 player_id TEXT PRIMARY KEY REFERENCES players(id),
 nick_key TEXT NOT NULL UNIQUE,
 game_nick TEXT NOT NULL,
 registered_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS native_lobby_levels (
 player_id TEXT PRIMARY KEY REFERENCES players(id),
 level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 1000));
CREATE TABLE IF NOT EXISTS native_lobby_currencies (
 player_id TEXT NOT NULL REFERENCES players(id), currency_id INTEGER NOT NULL,
 amount INTEGER NOT NULL CHECK(amount>=0), PRIMARY KEY(player_id,currency_id));
CREATE TABLE IF NOT EXISTS native_lobby_props (
 gid INTEGER PRIMARY KEY, player_id TEXT NOT NULL REFERENCES players(id),
 template_id INTEGER NOT NULL, quantity INTEGER NOT NULL CHECK(quantity>0),
 grid_page_id INTEGER NOT NULL, x INTEGER NOT NULL, y INTEGER NOT NULL,
 length INTEGER NOT NULL CHECK(length>0), width INTEGER NOT NULL CHECK(width>0),
 UNIQUE(player_id,grid_page_id,x,y));
CREATE TABLE IF NOT EXISTS native_lobby_collection_props (
 player_id TEXT NOT NULL REFERENCES players(id), template_id INTEGER NOT NULL,
 quantity INTEGER NOT NULL CHECK(quantity>0),
 PRIMARY KEY(player_id,template_id));
CREATE TABLE IF NOT EXISTS native_lobby_melee_props (
 player_id TEXT PRIMARY KEY REFERENCES players(id), template_id INTEGER NOT NULL,
 gid INTEGER NOT NULL UNIQUE CHECK(gid>0));
CREATE TABLE IF NOT EXISTS native_lobby_sort_configs (
 player_id TEXT PRIMARY KEY REFERENCES players(id), config_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS native_lobby_devices (
 player_id TEXT NOT NULL REFERENCES players(id), device_id INTEGER NOT NULL,
 level INTEGER NOT NULL CHECK(level>0), PRIMARY KEY(player_id,device_id));
CREATE TABLE IF NOT EXISTS native_lobby_selected_heroes (
 player_id TEXT PRIMARY KEY REFERENCES players(id), hero_id INTEGER NOT NULL CHECK(hero_id>0));
CREATE TABLE IF NOT EXISTS native_lobby_selected_heroes_by_mode (
 player_id TEXT NOT NULL REFERENCES players(id), mode INTEGER NOT NULL CHECK(mode>1),
 hero_id INTEGER NOT NULL CHECK(hero_id>0), PRIMARY KEY(player_id,mode));
CREATE TABLE IF NOT EXISTS containers (
 player_id TEXT NOT NULL REFERENCES players(id), name TEXT NOT NULL,
 width INTEGER NOT NULL CHECK(width>0), height INTEGER NOT NULL CHECK(height>0),
 PRIMARY KEY(player_id,name));
CREATE TABLE IF NOT EXISTS items (
 id TEXT PRIMARY KEY, player_id TEXT NOT NULL REFERENCES players(id), template_id TEXT NOT NULL,
 quantity INTEGER NOT NULL CHECK(quantity>0), container TEXT NOT NULL,
 x INTEGER NOT NULL, y INTEGER NOT NULL, rotated INTEGER NOT NULL CHECK(rotated IN (0,1)),
 equipped_slot TEXT,
 FOREIGN KEY(player_id,container) REFERENCES containers(player_id,name));
CREATE UNIQUE INDEX IF NOT EXISTS equipped_slot_unique ON items(player_id,equipped_slot)
 WHERE equipped_slot IS NOT NULL;
CREATE TABLE IF NOT EXISTS quests (
 player_id TEXT NOT NULL REFERENCES players(id), quest_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('accepted','completed','claimed')),
 progress TEXT NOT NULL, PRIMARY KEY(player_id,quest_id));
CREATE TABLE IF NOT EXISTS requests (
 player_id TEXT NOT NULL REFERENCES players(id), request_id TEXT NOT NULL,
 fingerprint TEXT NOT NULL, response TEXT NOT NULL, PRIMARY KEY(player_id,request_id));
CREATE TABLE IF NOT EXISTS events (
 player_id TEXT NOT NULL REFERENCES players(id), event_id TEXT NOT NULL,
 fingerprint TEXT NOT NULL, PRIMARY KEY(player_id,event_id));
CREATE TABLE IF NOT EXISTS audit (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, player_id TEXT NOT NULL REFERENCES players(id),
 operation TEXT NOT NULL, revision INTEGER NOT NULL, time INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Backend:
    PASSWORD_ITERATIONS = 600000
    READS = {"profile.get", "hall.get", "inventory.list", "quests.list"}
    WRITES = {"inventory.move", "inventory.split", "inventory.equip", "quests.accept",
              "quests.complete", "quests.claim", "quests.submit", "quests.abandon"}

    def __init__(self, database, definitions):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.definitions = json.loads(Path(definitions).read_text(encoding="utf-8"))
        self._validate_definitions()
        definition_hash = hashlib.sha256(canonical(self.definitions).encode()).hexdigest()
        with self.connection() as connection:
            connection.executescript(SCHEMA)
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute("SELECT value FROM metadata WHERE key='definitions_hash'").fetchone()
            if previous and previous[0] != definition_hash:
                fail("DEFINITIONS_CHANGED", "Existing save uses different definitions; migrate it or choose a new save path")
            connection.execute("INSERT OR IGNORE INTO metadata VALUES ('definitions_hash',?)", (definition_hash,))
            # Preserve old development saves, but retire their passwordless sessions.
            connection.execute("DELETE FROM sessions WHERE player_id NOT IN (SELECT player_id FROM accounts)")
            # Earlier local builds incorrectly put bought Mandel bricks in the
            # spatial deposit. The client reads them from CollectionServer.
            connection.execute(
                "INSERT INTO native_lobby_collection_props(player_id,template_id,quantity) "
                "SELECT player_id,template_id,SUM(quantity) FROM native_lobby_props "
                "WHERE template_id BETWEEN 16110000000 AND 16110099999 "
                "GROUP BY player_id,template_id "
                "ON CONFLICT(player_id,template_id) DO UPDATE SET "
                "quantity=quantity+excluded.quantity")
            connection.execute(
                "DELETE FROM native_lobby_props "
                "WHERE template_id BETWEEN 16110000000 AND 16110099999")
            connection.commit()

    def _validate_definitions(self):
        items = self.definitions.get("items", {})
        quests = self.definitions.get("quests", {})
        containers = self.definitions.get("containers", {})
        if not items or not containers:
            fail("INVALID_DEFINITIONS", "At least one item and container definition is required")
        for name, item in items.items():
            text_value(name, "item id")
            for key in ["width", "height", "max_stack"]:
                integer(item[key], key, 1, 10000)
            if not isinstance(item.get("slots", []), list) or not all(isinstance(s, str) for s in item.get("slots", [])):
                fail("INVALID_DEFINITIONS", "slots must be strings")
        for name, shape in containers.items():
            text_value(name, "container")
            integer(shape[0], "container width", 1, 100)
            integer(shape[1], "container height", 1, 100)
        if "warehouse" not in containers or "equipment" not in containers:
            fail("INVALID_DEFINITIONS", "warehouse and equipment containers are required")
        for quest_id, quest in quests.items():
            text_value(quest_id, "quest id")
            if not quest.get("objectives"):
                fail("INVALID_DEFINITIONS", "A quest needs an objective")
            for objective in quest["objectives"]:
                if objective["kind"] not in {"submit", "kill", "extract", "collect"}:
                    fail("INVALID_DEFINITIONS", "Unsupported objective kind")
                integer(objective["count"], "objective count", 1)
                text_value(objective["target"], "objective target")
                if objective["kind"] == "submit" and objective["target"] not in items:
                    fail("INVALID_DEFINITIONS", "Unknown submitted item")
            for prerequisite in quest.get("prerequisites", []):
                if prerequisite not in quests:
                    fail("INVALID_DEFINITIONS", "Unknown prerequisite")
            self._validate_rewards(quest.get("reward", {}))
        visited, visiting = set(), set()
        def visit(name):
            if name in visiting:
                fail("INVALID_DEFINITIONS", "Cyclic quest prerequisites")
            if name in visited:
                return
            visiting.add(name)
            for prerequisite in quests[name].get("prerequisites", []):
                visit(prerequisite)
            visiting.remove(name)
            visited.add(name)
        for name in quests:
            visit(name)
        self._validate_rewards({"items": self.definitions.get("starter_items", [])})

    def _validate_rewards(self, reward):
        integer(reward.get("money", 0), "reward money")
        integer(reward.get("xp", 0), "reward xp")
        for item in reward.get("items", []):
            if item["template_id"] not in self.definitions["items"]:
                fail("INVALID_DEFINITIONS", "Unknown reward item")
            integer(item["quantity"], "reward quantity", 1, 100000)

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.database, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _account_name(username):
        if not isinstance(username, str):
            fail("INVALID_ACCOUNT", "Username must be a string")
        display = unicodedata.normalize("NFKC", username).strip()
        if not 1 <= len(display) <= 64 or not all(c.isalnum() or c in "_.-" for c in display):
            fail("INVALID_ACCOUNT", "Username must contain 1 to 64 letters, numbers, dots, underscores or hyphens")
        return display, display.casefold()

    @staticmethod
    def _password_bytes(password):
        if not isinstance(password, str) or not 8 <= len(password) <= 128:
            fail("INVALID_PASSWORD", "Password must contain 8 to 128 characters")
        try:
            return password.encode("utf-8")
        except UnicodeError:
            fail("INVALID_PASSWORD", "Password must be valid Unicode")

    @classmethod
    def _password_verifier(cls, password, salt, iterations=None):
        return hashlib.pbkdf2_hmac("sha256", cls._password_bytes(password), salt,
                                   cls.PASSWORD_ITERATIONS if iterations is None else iterations)

    def register(self, username, password):
        local_name, username_key = self._account_name(username)
        salt = secrets.token_bytes(16)
        verifier = self._password_verifier(password, salt)
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if (connection.execute("SELECT 1 FROM accounts WHERE username_key=?", (username_key,)).fetchone()
                    or connection.execute("SELECT 1 FROM players WHERE local_name=?", (local_name,)).fetchone()):
                fail("ACCOUNT_EXISTS", "This local username is already reserved")
            player_id = "local-"+uuid.uuid4().hex
            connection.execute("INSERT INTO players(id,local_name) VALUES (?,?)", (player_id,local_name))
            connection.execute("INSERT INTO accounts VALUES (?,?,?,?,?)",
                               (username_key,player_id,salt,verifier,self.PASSWORD_ITERATIONS))
            for name, shape in self.definitions["containers"].items():
                connection.execute("INSERT INTO containers VALUES (?,?,?,?)", (player_id,name,*shape))
            for starter in self.definitions.get("starter_items", []):
                self._grant(connection,player_id,starter["template_id"],starter["quantity"])
            result = self._new_session(connection,player_id)
            connection.commit()
            return result

    def login(self, username, password=None):
        try:
            _, username_key = self._account_name(username)
            self._password_bytes(password)
        except DomainError:
            fail("UNAUTHORIZED", "Local username or password is incorrect")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM accounts WHERE username_key=?", (username_key,)).fetchone()
            # Perform a verifier calculation even for unknown accounts.
            salt = row["password_salt"] if row else bytes(16)
            iterations = row["password_iterations"] if row else self.PASSWORD_ITERATIONS
            actual = self._password_verifier(password,salt,iterations)
            if row is None or not hmac.compare_digest(actual,row["password_verifier"]):
                fail("UNAUTHORIZED", "Local username or password is incorrect")
            result = self._new_session(connection,row["player_id"])
            connection.commit()
            return result

    def _new_session(self, connection, player_id):
        token = secrets.token_urlsafe(32)
        expires = int(time.time())+86400
        connection.execute("DELETE FROM sessions WHERE expires<=?", (int(time.time()),))
        connection.execute("INSERT INTO sessions VALUES (?,?,?)", (self._token_hash(token),player_id,expires))
        profile = self._profile(connection,player_id)
        return {"session":token, "expires":expires, "profile":profile,
                "account":{"username":profile["local_name"],"provider":"local"}}

    def logout(self, token):
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._authorize(connection,token)
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (self._token_hash(token),))
            connection.commit()
        return {"logged_out":True}

    def change_password(self, token, current_password, new_password):
        salt = secrets.token_bytes(16)
        new_verifier = self._password_verifier(new_password,salt)
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection,token)
            row = connection.execute("SELECT * FROM accounts WHERE player_id=?", (player_id,)).fetchone()
            try:
                actual = self._password_verifier(current_password,row["password_salt"],row["password_iterations"])
            except DomainError:
                fail("UNAUTHORIZED", "Local username or password is incorrect")
            if not hmac.compare_digest(actual,row["password_verifier"]):
                fail("UNAUTHORIZED", "Local username or password is incorrect")
            connection.execute("UPDATE accounts SET password_salt=?,password_verifier=?,password_iterations=? WHERE player_id=?",
                               (salt,new_verifier,self.PASSWORD_ITERATIONS,player_id))
            connection.execute("DELETE FROM sessions WHERE player_id=?", (player_id,))
            result = self._new_session(connection,player_id)
            connection.commit()
            return result

    @staticmethod
    def _token_hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def _authorize(self, connection, token):
        text_value(token, "session", 256)
        row = connection.execute("SELECT sessions.player_id FROM sessions JOIN accounts USING(player_id) WHERE token_hash=? AND expires>?",
                                 (self._token_hash(token),int(time.time()))).fetchone()
        if row is None:
            fail("UNAUTHORIZED", "Local session is missing or expired")
        return row[0]

    def native_identity(self, token):
        """Resolve an authenticated local session for our native provider.

        This is our identity contract, not an official platform ticket or a
        current game login response. IDs are stable per local account.
        """
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            stored = connection.execute("SELECT native_id FROM native_identities WHERE player_id=?", (player_id,)).fetchone()
            if stored is None:
                for _ in range(8):
                    native_id = secrets.randbits(63)
                    if native_id and not connection.execute("SELECT 1 FROM native_identities WHERE native_id=?", (native_id,)).fetchone():
                        connection.execute("INSERT INTO native_identities VALUES (?,?)", (player_id,native_id))
                        break
                else:
                    fail("NATIVE_ID_UNAVAILABLE", "Could not allocate a local native identity")
            else:
                native_id = stored[0]
            expires = connection.execute("SELECT expires FROM sessions WHERE token_hash=?", (self._token_hash(token),)).fetchone()[0]
            profile = self._profile(connection, player_id)
            game_profile = connection.execute(
                "SELECT game_nick FROM game_profiles WHERE player_id=?", (player_id,)).fetchone()
            connection.commit()
            return {"provider":"local", "native_id":native_id, "username":profile["local_name"],
                    "game_nick":game_profile["game_nick"] if game_profile else None,
                    "game_registered":game_profile is not None, "expires":expires}

    def set_native_lobby_profile(self, token, *, level, currencies, props):
        """Provision one authenticated account's original-client lobby state."""
        integer(level, "level", 1, 1000)
        if not isinstance(currencies, dict) or not isinstance(props, list):
            fail("INVALID_ARGUMENT", "Expected currency mapping and warehouse prop list")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            connection.execute("INSERT INTO native_lobby_levels VALUES (?,?) ON CONFLICT(player_id) DO UPDATE SET level=excluded.level", (player_id, level))
            connection.execute("DELETE FROM native_lobby_currencies WHERE player_id=?", (player_id,))
            for currency_id, amount in currencies.items():
                integer(currency_id, "currency_id", 1, 2**63-1)
                integer(amount, "currency_amount", 0, 2**63-1)
                connection.execute("INSERT INTO native_lobby_currencies VALUES (?,?,?)", (player_id, currency_id, amount))
            connection.execute("DELETE FROM native_lobby_props WHERE player_id=?", (player_id,))
            connection.execute("DELETE FROM native_lobby_collection_props WHERE player_id=?", (player_id,))
            for prop in props:
                values = {name: integer(prop[name], name, minimum, maximum)
                          for name, minimum, maximum in (
                              ("gid", 1, 2**63-1), ("template_id", 1, 2**63-1),
                              ("quantity", 1, 2**31-1), ("grid_page_id", 1, 2**31-1),
                              ("x", 0, 2**31-1), ("y", 0, 2**31-1),
                              ("length", 1, 100), ("width", 1, 100))}
                connection.execute("INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)",
                                   (values["gid"], player_id, values["template_id"],
                                    values["quantity"], values["grid_page_id"],
                                    values["x"], values["y"], values["length"], values["width"]))
            connection.commit()

    def native_lobby_profile(self, token):
        with self.connection() as connection:
            player_id = self._authorize(connection, token)
            level = connection.execute("SELECT level FROM native_lobby_levels WHERE player_id=?", (player_id,)).fetchone()
            currencies = connection.execute(
                "SELECT currency_id,amount FROM native_lobby_currencies WHERE player_id=? ORDER BY currency_id", (player_id,)).fetchall()
            props = connection.execute(
                "SELECT gid,template_id,quantity,grid_page_id,x,y,length,width FROM native_lobby_props WHERE player_id=? ORDER BY y,x", (player_id,)).fetchall()
            collection_props = connection.execute(
                "SELECT template_id,quantity FROM native_lobby_collection_props "
                "WHERE player_id=? ORDER BY template_id", (player_id,)).fetchall()
            melee_props = connection.execute(
                "SELECT template_id,gid FROM native_lobby_melee_props WHERE player_id=?",
                (player_id,)).fetchall()
            sort_config = connection.execute(
                "SELECT config_json FROM native_lobby_sort_configs WHERE player_id=?", (player_id,)).fetchone()
            devices = connection.execute(
                "SELECT device_id,level FROM native_lobby_devices WHERE player_id=? ORDER BY device_id", (player_id,)).fetchall()
            selected_hero = connection.execute(
                "SELECT hero_id FROM native_lobby_selected_heroes WHERE player_id=?", (player_id,)).fetchone()
            selected_mp_hero = connection.execute(
                "SELECT hero_id FROM native_lobby_selected_heroes_by_mode "
                "WHERE player_id=? AND mode=2", (player_id,)).fetchone()
            return {"level": level[0] if level else 1,
                    "currencies": [dict(row) for row in currencies],
                    "props": [dict(row) for row in props],
                    "collection_props": [dict(row) for row in collection_props],
                    "melee_props": [dict(row) for row in melee_props],
                    "devices": [dict(row) for row in devices],
                    "selected_hero_id": selected_hero[0] if selected_hero else None,
                    "selected_mp_hero_id": selected_mp_hero[0] if selected_mp_hero else None,
                    "sort_config": json.loads(sort_config[0]) if sort_config else
                                   {"sort_style": 0, "sort_every_enter": False, "has_sorted": True}}

    def ensure_native_lobby_default_melee(self, token, template_id):
        """Give a local account one stable default melee item on first fetch."""
        integer(template_id, "template_id", 1, 2**63-1)
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            player = connection.execute("SELECT rowid FROM players WHERE id=?", (player_id,)).fetchone()
            gid = 6200000000000000000 + player[0]
            connection.execute(
                "INSERT OR IGNORE INTO native_lobby_melee_props VALUES (?,?,?)",
                (player_id, template_id, gid))
            row = connection.execute(
                "SELECT template_id,gid FROM native_lobby_melee_props WHERE player_id=?",
                (player_id,)).fetchone()
            connection.commit()
            return dict(row)

    def native_lobby_purchase(self, token, *, template_id, quantity, unit_price,
                              currency_id, length, width, max_stack_count=1,
                              bonus_currency_id=None, bonus_currency_amount=0,
                              target_position=2):
        """Atomically charge an account and place props at the requested slot."""
        for name, value, maximum in (
            ("template_id", template_id, 2**63-1), ("quantity", quantity, 1000),
            ("unit_price", unit_price, 2**63-1), ("currency_id", currency_id, 2**63-1),
            ("length", length, 9), ("width", width, 40),
            ("max_stack_count", max_stack_count, 1000),
        ):
            integer(value, name, 1, maximum)
        integer(target_position, "target_position", 2, 138)
        if target_position != 2 and (target_position < 101 or quantity != 1):
            fail("INVALID_ARGUMENT", "Equipment purchase requires one body-slot item")
        if unit_price * quantity >= 2**63:
            fail("INVALID_ARGUMENT", "Purchase total is too large")
        if bonus_currency_id is not None:
            integer(bonus_currency_id, "bonus_currency_id", 1, 2**63-1)
            integer(bonus_currency_amount, "bonus_currency_amount", 1, 2**63-1)
            if bonus_currency_id == currency_id:
                fail("INVALID_ARGUMENT", "Purchase bonus must use a different currency")
        elif bonus_currency_amount:
            fail("INVALID_ARGUMENT", "Purchase bonus has no currency identifier")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            balance = connection.execute(
                "SELECT amount FROM native_lobby_currencies WHERE player_id=? AND currency_id=?",
                (player_id, currency_id)).fetchone()
            total = unit_price * quantity
            if balance is None or balance[0] < total:
                fail("INSUFFICIENT_FUNDS", "Not enough local currency")
            placements = []
            displaced_props = []
            if target_position == 2:
                occupied = set()
                for prop in connection.execute(
                    "SELECT x,y,length,width FROM native_lobby_props WHERE player_id=? AND grid_page_id=2",
                    (player_id,)):
                    occupied.update((x, y) for x in range(prop["x"], prop["x"] + prop["length"])
                                    for y in range(prop["y"], prop["y"] + prop["width"]))
                remaining = quantity
                while remaining:
                    position = next(((x, y) for y in range(41 - width)
                                     for x in range(10 - length)
                                     if all((cx, cy) not in occupied
                                            for cx in range(x, x + length)
                                            for cy in range(y, y + width))), None)
                    if position is None:
                        fail("WAREHOUSE_FULL", "No room for the purchased prop")
                    x, y = position
                    occupied.update((cx, cy) for cx in range(x, x + length)
                                    for cy in range(y, y + width))
                    stack = min(remaining, max_stack_count)
                    placements.append((x, y, stack))
                    remaining -= stack
            else:
                occupied_slot = connection.execute(
                    "SELECT * FROM native_lobby_props WHERE player_id=? AND grid_page_id=?",
                    (player_id, target_position)).fetchone()
                if occupied_slot:
                    occupied = set()
                    for prop in connection.execute(
                        "SELECT x,y,length,width FROM native_lobby_props "
                        "WHERE player_id=? AND grid_page_id=2", (player_id,)):
                        occupied.update((x, y) for x in range(prop["x"], prop["x"] + prop["length"])
                                        for y in range(prop["y"], prop["y"] + prop["width"]))
                    old_length, old_width = occupied_slot["length"], occupied_slot["width"]
                    old_position = next(((x, y) for y in range(41 - old_width)
                                         for x in range(10 - old_length)
                                         if all((cx, cy) not in occupied
                                                for cx in range(x, x + old_length)
                                                for cy in range(y, y + old_width))), None)
                    if old_position is None:
                        fail("WAREHOUSE_FULL", "No room for the replaced equipment")
                    old_x, old_y = old_position
                    connection.execute(
                        "UPDATE native_lobby_props SET grid_page_id=2,x=?,y=? "
                        "WHERE gid=? AND player_id=?",
                        (old_x, old_y, occupied_slot["gid"], player_id))
                    displaced_props.append({"before": dict(occupied_slot), "after": {
                        **dict(occupied_slot), "grid_page_id": 2,
                        "x": old_x, "y": old_y}})
                placements.append((0, 0, 1))
            next_gid = connection.execute(
                "SELECT MAX(gid) FROM native_lobby_props").fetchone()[0]
            next_gid = max(6300000000000000000, next_gid or 0) + 1
            if next_gid + len(placements) >= 2**63:
                fail("WAREHOUSE_FULL", "Local prop identifier range is exhausted")
            created = []
            for x, y, stack in placements:
                connection.execute("INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)",
                                   (next_gid, player_id, template_id, stack, target_position,
                                    x, y, length, width))
                created.append({"gid": next_gid, "template_id": template_id,
                                "quantity": stack, "grid_page_id": target_position,
                                "x": x, "y": y, "length": length, "width": width})
                next_gid += 1
            current = balance[0] - total
            connection.execute(
                "UPDATE native_lobby_currencies SET amount=? WHERE player_id=? AND currency_id=?",
                (current, player_id, currency_id))
            bonus_change = None
            if bonus_currency_id is not None:
                bonus_before = connection.execute(
                    "SELECT amount FROM native_lobby_currencies WHERE player_id=? AND currency_id=?",
                    (player_id, bonus_currency_id)).fetchone()
                bonus_current = (bonus_before[0] if bonus_before else 0) + bonus_currency_amount
                if bonus_current >= 2**63:
                    fail("INVALID_ARGUMENT", "Purchase bonus balance is too large")
                connection.execute(
                    "INSERT INTO native_lobby_currencies VALUES (?,?,?) "
                    "ON CONFLICT(player_id,currency_id) DO UPDATE SET amount=excluded.amount",
                    (player_id, bonus_currency_id, bonus_current))
                bonus_change = {"currency_id": bonus_currency_id,
                                "delta": bonus_currency_amount,
                                "current_num": bonus_current}
            connection.commit()
            return {"props": created, "currency_id": currency_id,
                    "currency_delta": -total, "currency_current": current,
                    "bonus_currency_change": bonus_change,
                    "displaced_props": displaced_props}

    def native_lobby_move_props(self, token, commands):
        """Apply authenticated warehouse/equipment moves as one transaction."""
        if not isinstance(commands, list) or not 1 <= len(commands) <= 32:
            fail("INVALID_ARGUMENT", "Expected one or more equipment moves")
        changes = []
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)

            def warehouse_position(length, width, ignored, preferred=None):
                occupied = set()
                for row in connection.execute(
                        "SELECT gid,x,y,length,width FROM native_lobby_props "
                        "WHERE player_id=? AND grid_page_id=2", (player_id,)):
                    if row["gid"] not in ignored:
                        occupied.update((x, y) for x in range(row["x"], row["x"] + row["length"])
                                        for y in range(row["y"], row["y"] + row["width"]))

                def fits(x, y):
                    return (0 <= x <= 9 - length and 0 <= y <= 40 - width
                            and all((cx, cy) not in occupied
                                    for cx in range(x, x + length)
                                    for cy in range(y, y + width)))

                if preferred is not None and fits(*preferred):
                    return preferred
                location = next(((x, y) for y in range(41 - width)
                                 for x in range(10 - length) if fits(x, y)), None)
                if location is None:
                    fail("WAREHOUSE_FULL", "No room for the moved prop")
                return location

            for command in commands:
                gid = integer(command.get("prop_gid"), "prop_gid", 1, 2**63 - 1)
                target = integer(command.get("target_pos"), "target_pos", 2, 138)
                if target != 2 and target < 101:
                    fail("INVALID_ARGUMENT", "Unsupported equipment position")
                row = connection.execute(
                    "SELECT * FROM native_lobby_props WHERE player_id=? AND gid=?",
                    (player_id, gid)).fetchone()
                if row is None:
                    fail("PROP_NOT_FOUND", "The moved prop is not in this account")
                source = row["grid_page_id"]
                if int(command.get("prop_id") or row["template_id"]) != row["template_id"]:
                    fail("INVALID_ARGUMENT", "Moved prop template does not match")
                if int(command.get("src_pos") or source) != source:
                    fail("INVALID_ARGUMENT", "Moved prop source position does not match")
                if int(command.get("num") or row["quantity"]) != row["quantity"]:
                    fail("INVALID_ARGUMENT", "Partial stack movement is not supported")
                if source == target and target != 2:
                    fail("INVALID_ARGUMENT", "The prop is already in that equipment slot")
                if source != 2 and not 101 <= source <= 138:
                    fail("INVALID_ARGUMENT", "Unsupported source position")
                old = dict(row)
                incumbent = None
                if target != 2:
                    incumbent = connection.execute(
                        "SELECT * FROM native_lobby_props WHERE player_id=? "
                        "AND grid_page_id=? AND gid<>?", (player_id, target, gid)).fetchone()
                    if incumbent is not None:
                        expected_gid = int(command.get("target_prop_gid") or 0)
                        if expected_gid and expected_gid != incumbent["gid"]:
                            fail("POSITION_OCCUPIED", "The equipment slot changed during the move")
                preferred = None
                if target == 2:
                    loc = command.get("spec_loc") or {}
                    if int(loc.get("pos") or 2) == 2 and "start_x" in loc and "start_y" in loc:
                        preferred = (int(loc["start_x"]), int(loc["start_y"]))
                    x, y = warehouse_position(row["length"], row["width"], {gid}, preferred)
                else:
                    x = y = 0

                # Vacate the source first to satisfy the unique slot-origin index.
                connection.execute(
                    "UPDATE native_lobby_props SET grid_page_id=?,x=0,y=0 "
                    "WHERE gid=? AND player_id=?", (999999, gid, player_id))
                if incumbent is not None:
                    displaced = dict(incumbent)
                    if source == 2:
                        displaced_target = 2
                        dx, dy = warehouse_position(
                            displaced["length"], displaced["width"], {gid},
                            (old["x"], old["y"]))
                    else:
                        displaced_target, dx, dy = source, 0, 0
                    connection.execute(
                        "UPDATE native_lobby_props SET grid_page_id=?,x=?,y=? "
                        "WHERE gid=? AND player_id=?",
                        (displaced_target, dx, dy, displaced["gid"], player_id))
                    changes.append({"before": displaced, "after": {
                        **displaced, "grid_page_id": displaced_target, "x": dx, "y": dy}})
                connection.execute(
                    "UPDATE native_lobby_props SET grid_page_id=?,x=?,y=? "
                    "WHERE gid=? AND player_id=?", (target, x, y, gid, player_id))
                changes.append({"before": old, "after": {
                    **old, "grid_page_id": target, "x": x, "y": y}})
            connection.commit()
        return changes

    def native_lobby_collection_purchase(self, token, *, template_id, quantity,
                                         unit_price, currency_id,
                                         bonus_currency_id=None,
                                         bonus_currency_amount=0):
        """Atomically debit a Mandel purchase into CollectionServer state."""
        for name, value, maximum in (
            ("template_id", template_id, 2**63-1), ("quantity", quantity, 1000),
            ("unit_price", unit_price, 2**63-1),
            ("currency_id", currency_id, 2**63-1),
        ):
            integer(value, name, 1, maximum)
        if bonus_currency_id is not None:
            integer(bonus_currency_id, "bonus_currency_id", 1, 2**63-1)
            integer(bonus_currency_amount, "bonus_currency_amount", 1, 2**63-1)
            if bonus_currency_id == currency_id:
                fail("INVALID_ARGUMENT", "Purchase bonus must use a different currency")
        elif bonus_currency_amount:
            fail("INVALID_ARGUMENT", "Purchase bonus has no currency identifier")
        total = unit_price * quantity
        if total >= 2**63:
            fail("INVALID_ARGUMENT", "Purchase total is too large")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            balance = connection.execute(
                "SELECT amount FROM native_lobby_currencies "
                "WHERE player_id=? AND currency_id=?",
                (player_id, currency_id)).fetchone()
            if balance is None or balance[0] < total:
                fail("INSUFFICIENT_FUNDS", "Not enough local currency")
            before = connection.execute(
                "SELECT quantity FROM native_lobby_collection_props "
                "WHERE player_id=? AND template_id=?",
                (player_id, template_id)).fetchone()
            current_quantity = (before[0] if before else 0) + quantity
            if current_quantity >= 2**31:
                fail("INVALID_ARGUMENT", "Collection stack is too large")
            connection.execute(
                "INSERT INTO native_lobby_collection_props VALUES (?,?,?) "
                "ON CONFLICT(player_id,template_id) DO UPDATE SET "
                "quantity=excluded.quantity",
                (player_id, template_id, current_quantity))
            current = balance[0] - total
            connection.execute(
                "UPDATE native_lobby_currencies SET amount=? "
                "WHERE player_id=? AND currency_id=?",
                (current, player_id, currency_id))
            bonus_change = None
            if bonus_currency_id is not None:
                bonus_before = connection.execute(
                    "SELECT amount FROM native_lobby_currencies "
                    "WHERE player_id=? AND currency_id=?",
                    (player_id, bonus_currency_id)).fetchone()
                bonus_current = (bonus_before[0] if bonus_before else 0) + bonus_currency_amount
                if bonus_current >= 2**63:
                    fail("INVALID_ARGUMENT", "Purchase bonus balance is too large")
                connection.execute(
                    "INSERT INTO native_lobby_currencies VALUES (?,?,?) "
                    "ON CONFLICT(player_id,currency_id) DO UPDATE SET amount=excluded.amount",
                    (player_id, bonus_currency_id, bonus_current))
                bonus_change = {"currency_id": bonus_currency_id,
                                "delta": bonus_currency_amount,
                                "current_num": bonus_current}
            connection.commit()
            return {"collection_prop": {"template_id": template_id,
                                         "quantity": current_quantity,
                                         "delta": quantity},
                    "currency_id": currency_id, "currency_delta": -total,
                    "currency_current": current,
                    "bonus_currency_change": bonus_change}

    def set_native_selected_hero(self, token, hero_id):
        """Persist the account's SOL operator (WorldGameMode=1)."""
        integer(hero_id, "hero_id", 1, 2**63-1)
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            connection.execute(
                "INSERT INTO native_lobby_selected_heroes VALUES (?,?) "
                "ON CONFLICT(player_id) DO UPDATE SET hero_id=excluded.hero_id",
                (player_id, hero_id))
            connection.commit()

    def set_native_selected_hero_for_mode(self, token, hero_id, mode):
        """Keep non-SOL lobby selections separate from the SOL room operator."""
        integer(mode, "mode", 1, 2**31-1)
        if mode == 1:
            return self.set_native_selected_hero(token, hero_id)
        integer(hero_id, "hero_id", 1, 2**63-1)
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            connection.execute(
                "INSERT INTO native_lobby_selected_heroes_by_mode VALUES (?,?,?) "
                "ON CONFLICT(player_id,mode) DO UPDATE SET hero_id=excluded.hero_id",
                (player_id, mode, hero_id))
            connection.commit()

    def set_native_lobby_devices(self, token, devices):
        """Replace one account's safehouse devices with validated local IDs/levels."""
        if not isinstance(devices, dict):
            fail("INVALID_ARGUMENT", "Device levels must be a mapping")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            connection.execute("DELETE FROM native_lobby_devices WHERE player_id=?", (player_id,))
            for device_id, level in devices.items():
                integer(device_id, "device_id", 1, 2**31-1)
                integer(level, "device_level", 1, 1000)
                connection.execute("INSERT INTO native_lobby_devices VALUES (?,?,?)",
                                   (player_id, device_id, level))
            connection.commit()

    def set_native_lobby_sort_config(self, token, config):
        if not isinstance(config, dict):
            fail("INVALID_ARGUMENT", "Sort configuration must be an object")
        allowed = {"sort_style", "sort_class_order", "extension_first_class",
                   "sort_every_enter", "has_sorted"}
        if set(config) - allowed:
            fail("INVALID_ARGUMENT", "Sort configuration has unknown fields")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            connection.execute("INSERT INTO native_lobby_sort_configs VALUES (?,?) ON CONFLICT(player_id) DO UPDATE SET config_json=excluded.config_json",
                               (player_id, canonical(config)))
            connection.commit()
        return config

    @staticmethod
    def _game_nick(value):
        if not isinstance(value, str):
            fail("INVALID_GAME_NICK", "Character name must be text")
        nick = unicodedata.normalize("NFKC", value).strip()
        if not 1 <= len(nick) <= 16 or len(nick.encode("utf-8")) > 64 or not nick.isprintable():
            fail("INVALID_GAME_NICK", "Character name must be printable and at most 16 characters or 64 bytes")
        return nick, nick.casefold()

    def validate_game_nick(self, token, value):
        nick, key = self._game_nick(value)
        with self.connection() as connection:
            player_id = self._authorize(connection, token)
            owner = connection.execute(
                "SELECT player_id FROM game_profiles WHERE nick_key=?", (key,)).fetchone()
            return {"game_nick":nick, "available":owner is None or owner["player_id"] == player_id}

    def register_game_nick(self, token, value):
        nick, key = self._game_nick(value)
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            existing = connection.execute(
                "SELECT game_nick,nick_key FROM game_profiles WHERE player_id=?", (player_id,)).fetchone()
            if existing:
                if existing["nick_key"] != key:
                    fail("GAME_PROFILE_EXISTS", "This local account already has a character name")
                return {"game_nick":existing["game_nick"], "registered":True}
            if connection.execute("SELECT 1 FROM game_profiles WHERE nick_key=?", (key,)).fetchone():
                fail("GAME_NICK_EXISTS", "Character name is already in use")
            connection.execute("INSERT INTO game_profiles VALUES (?,?,?,?)",
                               (player_id,key,nick,int(time.time())))
            connection.execute("UPDATE players SET revision=revision+1 WHERE id=?", (player_id,))
            connection.execute("INSERT INTO audit(player_id,operation,revision,time) VALUES (?,?,?,?)",
                               (player_id,"game_profile.register",self._profile(connection,player_id)["revision"],int(time.time())))
            connection.commit()
            return {"game_nick":nick, "registered":True}

    def dispatch(self, token, operation, payload=None, request_id=None, expected_revision=None):
        if operation not in self.READS | self.WRITES:
            fail("UNSUPPORTED_OPERATION", "Operation has no implemented local handler")
        payload = {} if payload is None else payload
        if not isinstance(payload, dict):
            fail("INVALID_ARGUMENT", "payload must be an object")
        fingerprint = hashlib.sha256(canonical([operation,payload,expected_revision]).encode()).hexdigest()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            player_id = self._authorize(connection, token)
            mutation = operation in self.WRITES
            if mutation:
                text_value(request_id, "request_id")
                previous = connection.execute("SELECT * FROM requests WHERE player_id=? AND request_id=?",
                                              (player_id,request_id)).fetchone()
                if previous:
                    if previous["fingerprint"] != fingerprint:
                        fail("REQUEST_ID_CONFLICT", "request_id was used with a different request")
                    return json.loads(previous["response"])
                integer(expected_revision, "expected_revision")
                if self._profile(connection,player_id)["revision"] != expected_revision:
                    fail("STALE_REVISION", "Reload state before applying another change")
            result = self._handle(connection, player_id, operation, payload)
            if mutation:
                connection.execute("UPDATE players SET revision=revision+1 WHERE id=?", (player_id,))
                if isinstance(result, dict) and "profile" in result:
                    result["profile"] = self._profile(connection,player_id)
            response = {"data":result, "revision":self._profile(connection,player_id)["revision"]}
            if mutation:
                connection.execute("INSERT INTO requests VALUES (?,?,?,?)",
                                   (player_id,request_id,fingerprint,canonical(response)))
                connection.execute("INSERT INTO audit(player_id,operation,revision,time) VALUES (?,?,?,?)",
                                   (player_id,operation,response["revision"],int(time.time())))
            connection.commit()
            return response

    def _profile(self, connection, player_id):
        row = connection.execute("SELECT * FROM players WHERE id=?", (player_id,)).fetchone()
        if row is None:
            fail("NOT_FOUND", "Local player does not exist")
        return dict(row)

    def _inventory(self, connection, player_id):
        return {"containers":[dict(row) for row in connection.execute(
                    "SELECT name,width,height FROM containers WHERE player_id=? ORDER BY name", (player_id,))],
                "items":[dict(row) for row in connection.execute(
                    "SELECT id,template_id,quantity,container,x,y,rotated,equipped_slot FROM items WHERE player_id=? ORDER BY id", (player_id,))]}

    def _item(self, connection, player_id, instance_id):
        text_value(instance_id, "instance_id")
        row = connection.execute("SELECT * FROM items WHERE id=? AND player_id=?", (instance_id,player_id)).fetchone()
        if row is None:
            fail("NOT_FOUND", "Item instance does not belong to this player")
        return dict(row)

    def _dimensions(self, item):
        definition = self.definitions["items"][item["template_id"]]
        width, height = definition["width"], definition["height"]
        return (height,width) if item["rotated"] else (width,height)

    def _position(self, connection, player_id, item, container, x, y, rotated):
        text_value(container, "container")
        integer(x, "x")
        integer(y, "y")
        if type(rotated) is not bool:
            fail("INVALID_ARGUMENT", "rotated must be a boolean")
        if container == "equipment":
            fail("INVALID_ARGUMENT", "Use inventory.equip for an equipment slot")
        shape = connection.execute("SELECT width,height FROM containers WHERE player_id=? AND name=?",
                                   (player_id,container)).fetchone()
        if shape is None:
            fail("NOT_FOUND", "Container does not exist")
        candidate = dict(item,rotated=rotated)
        width,height = self._dimensions(candidate)
        if x+width > shape[0] or y+height > shape[1]:
            fail("OUT_OF_BOUNDS", "Item rectangle extends outside container")
        for occupied in connection.execute("SELECT * FROM items WHERE player_id=? AND container=? AND id<>?",
                                           (player_id,container,item.get("id", ""))):
            other_width,other_height = self._dimensions(occupied)
            if x < occupied["x"]+other_width and x+width > occupied["x"] and y < occupied["y"]+other_height and y+height > occupied["y"]:
                fail("POSITION_OCCUPIED", "Item overlaps another instance")
        return container,x,y,int(rotated)

    def _grant(self, connection, player_id, template_id, quantity):
        if template_id not in self.definitions["items"]:
            fail("UNKNOWN_TEMPLATE", "Item definition is missing")
        integer(quantity, "quantity", 1, 100000)
        definition = self.definitions["items"][template_id]
        shape = connection.execute("SELECT width,height FROM containers WHERE player_id=? AND name='warehouse'", (player_id,)).fetchone()
        instances = []
        while quantity:
            new_item = {"template_id":template_id, "rotated":False}
            position = None
            for y in range(shape[1]):
                for x in range(shape[0]):
                    try:
                        position = self._position(connection,player_id,new_item,"warehouse",x,y,False)
                        break
                    except DomainError as error:
                        if error.code not in {"POSITION_OCCUPIED", "OUT_OF_BOUNDS"}:
                            raise
                if position:
                    break
            if not position:
                fail("WAREHOUSE_FULL", "Reward or starter items do not fit; transaction rolled back")
            instance_id = uuid.uuid4().hex
            amount = min(quantity,definition["max_stack"])
            connection.execute("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,NULL)",
                               (instance_id,player_id,template_id,amount,*position))
            instances.append(instance_id)
            quantity -= amount
        return instances

    def _quest_definition(self, quest_id):
        text_value(quest_id, "quest_id")
        if quest_id not in self.definitions["quests"]:
            fail("NOT_FOUND", "Quest definition does not exist")
        return self.definitions["quests"][quest_id]

    def _quest(self, connection, player_id, quest_id):
        self._quest_definition(quest_id)
        row = connection.execute("SELECT * FROM quests WHERE player_id=? AND quest_id=?", (player_id,quest_id)).fetchone()
        if row is None:
            fail("QUEST_NOT_ACCEPTED", "Accept the quest first")
        result = dict(row)
        result["progress"] = json.loads(result["progress"])
        return result

    def _quests(self, connection, player_id):
        stored = {row["quest_id"]:dict(row) for row in connection.execute("SELECT * FROM quests WHERE player_id=?", (player_id,))}
        result = []
        for quest_id, definition in self.definitions["quests"].items():
            row = stored.get(quest_id)
            unlocked = all(stored.get(key,{}).get("status") == "claimed" for key in definition.get("prerequisites", []))
            result.append({"quest_id":quest_id,"definition":definition,
                           "status":row["status"] if row else ("available" if unlocked else "locked"),
                           "progress":json.loads(row["progress"]) if row else [0]*len(definition["objectives"])})
        return result

    def _handle(self, connection, player_id, operation, payload):
        if operation == "profile.get":
            return self._profile(connection,player_id)
        if operation == "hall.get":
            return {"profile":self._profile(connection,player_id), "inventory":self._inventory(connection,player_id),
                    "quests":self._quests(connection,player_id), "battle_server_available":False}
        if operation == "inventory.list":
            return self._inventory(connection,player_id)
        if operation == "quests.list":
            return self._quests(connection,player_id)
        if operation in {"inventory.move", "inventory.split", "inventory.equip"}:
            item = self._item(connection,player_id,payload.get("instance_id"))
            if operation == "inventory.equip":
                slot = text_value(payload.get("slot"), "slot")
                definition = self.definitions["items"][item["template_id"]]
                if slot not in definition.get("slots", []) or item["quantity"] != 1:
                    fail("INVALID_EQUIPMENT", "Template or stack cannot use this equipment slot")
                occupied = connection.execute("SELECT id FROM items WHERE player_id=? AND equipped_slot=? AND id<>?",
                                              (player_id,slot,item["id"])).fetchone()
                if occupied:
                    fail("SLOT_OCCUPIED", "Move the current equipment to a container first")
                connection.execute("UPDATE items SET container='equipment',x=0,y=0,rotated=0,equipped_slot=? WHERE id=?", (slot,item["id"]))
            else:
                if operation == "inventory.split":
                    amount = integer(payload.get("quantity"), "quantity", 1)
                    if item["equipped_slot"] is not None or amount >= item["quantity"]:
                        fail("INVALID_STACK_SPLIT", "Split quantity must be smaller than an unequipped stack")
                    position_item = dict(item,id="")
                else:
                    position_item = item
                position = self._position(connection,player_id,position_item,payload.get("container"),payload.get("x"),payload.get("y"),payload.get("rotated",False))
                if operation == "inventory.split":
                    new_id = uuid.uuid4().hex
                    connection.execute("UPDATE items SET quantity=quantity-? WHERE id=?", (amount,item["id"]))
                    connection.execute("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,NULL)", (new_id,player_id,item["template_id"],amount,*position))
                else:
                    connection.execute("UPDATE items SET container=?,x=?,y=?,rotated=?,equipped_slot=NULL WHERE id=?", (*position,item["id"]))
            return self._inventory(connection,player_id)
        quest_id = payload.get("quest_id")
        definition = self._quest_definition(quest_id)
        if operation == "quests.accept":
            existing = connection.execute("SELECT status FROM quests WHERE player_id=? AND quest_id=?", (player_id,quest_id)).fetchone()
            if existing:
                fail("QUEST_ALREADY_ACCEPTED", "Quest is already in the player's save")
            for prerequisite in definition.get("prerequisites", []):
                row = connection.execute("SELECT status FROM quests WHERE player_id=? AND quest_id=?", (player_id,prerequisite)).fetchone()
                if row is None or row[0] != "claimed":
                    fail("QUEST_LOCKED", "Claim prerequisite quest rewards first")
            connection.execute("INSERT INTO quests VALUES (?,?,'accepted',?)", (player_id,quest_id,canonical([0]*len(definition["objectives"]))))
        else:
            quest = self._quest(connection,player_id,quest_id)
            if operation == "quests.abandon":
                if quest["status"] != "accepted":
                    fail("INVALID_QUEST_STATE", "Only an accepted quest can be abandoned")
                connection.execute("DELETE FROM quests WHERE player_id=? AND quest_id=?", (player_id,quest_id))
            elif operation == "quests.complete":
                if quest["status"] != "accepted":
                    fail("INVALID_QUEST_STATE", "Quest must be accepted to complete")
                if not all(value >= objective["count"] for value,objective in zip(quest["progress"],definition["objectives"])):
                    fail("OBJECTIVES_INCOMPLETE", "Quest objectives are incomplete")
                connection.execute("UPDATE quests SET status='completed' WHERE player_id=? AND quest_id=?", (player_id,quest_id))
            elif operation == "quests.claim":
                if quest["status"] != "completed":
                    fail("INVALID_QUEST_STATE", "Quest reward is unavailable or already claimed")
                reward = definition.get("reward", {})
                for item in reward.get("items", []):
                    self._grant(connection,player_id,item["template_id"],item["quantity"])
                connection.execute("UPDATE players SET money=money+?,xp=xp+? WHERE id=?", (reward.get("money",0),reward.get("xp",0),player_id))
                connection.execute("UPDATE quests SET status='claimed' WHERE player_id=? AND quest_id=?", (player_id,quest_id))
            elif operation == "quests.submit":
                if quest["status"] != "accepted":
                    fail("INVALID_QUEST_STATE", "Quest must be accepted to submit items")
                index = integer(payload.get("objective_index"), "objective_index", 0, len(definition["objectives"])-1)
                objective = definition["objectives"][index]
                item = self._item(connection,player_id,payload.get("instance_id"))
                amount = integer(payload.get("quantity"), "quantity", 1)
                if objective["kind"] != "submit" or objective["target"] != item["template_id"]:
                    fail("WRONG_QUEST_ITEM", "Item does not match the selected submission objective")
                if item["equipped_slot"] is not None or amount > item["quantity"] or amount > objective["count"]-quest["progress"][index]:
                    fail("INVALID_SUBMISSION", "Quantity exceeds the stack or remaining objective")
                if amount == item["quantity"]:
                    connection.execute("DELETE FROM items WHERE id=?", (item["id"],))
                else:
                    connection.execute("UPDATE items SET quantity=quantity-? WHERE id=?", (amount,item["id"]))
                quest["progress"][index] += amount
                connection.execute("UPDATE quests SET progress=? WHERE player_id=? AND quest_id=?", (canonical(quest["progress"]),player_id,quest_id))
        return {"quests":self._quests(connection,player_id),"profile":self._profile(connection,player_id),"inventory":self._inventory(connection,player_id)}

    def record_event(self, player_id, event_id, kind, target, amount):
        """Trusted local simulation interface; never called from a client claim request."""
        text_value(player_id, "player_id")
        text_value(event_id, "event_id")
        text_value(target, "target")
        integer(amount, "amount", 1, 100000)
        if kind not in {"kill", "extract", "collect"}:
            fail("INVALID_EVENT", "Event kind is unsupported; submitted items use quests.submit")
        fingerprint = hashlib.sha256(canonical([kind,target,amount]).encode()).hexdigest()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._profile(connection,player_id)
            existing = connection.execute("SELECT fingerprint FROM events WHERE player_id=? AND event_id=?", (player_id,event_id)).fetchone()
            if existing:
                if existing[0] != fingerprint:
                    fail("EVENT_ID_CONFLICT", "Event ID already has a different payload")
                return {"applied":False}
            for row in connection.execute("SELECT * FROM quests WHERE player_id=? AND status='accepted'", (player_id,)):
                definition = self._quest_definition(row["quest_id"])
                progress = json.loads(row["progress"])
                for index,objective in enumerate(definition["objectives"]):
                    if objective["kind"] == kind and objective["target"] == target:
                        progress[index] = min(objective["count"],progress[index]+amount)
                connection.execute("UPDATE quests SET progress=? WHERE player_id=? AND quest_id=?", (canonical(progress),player_id,row["quest_id"]))
            connection.execute("INSERT INTO events VALUES (?,?,?)", (player_id,event_id,fingerprint))
            connection.execute("UPDATE players SET revision=revision+1 WHERE id=?", (player_id,))
            revision = self._profile(connection,player_id)["revision"]
            connection.execute("INSERT INTO audit(player_id,operation,revision,time) VALUES (?,'trusted.event',?,?)", (player_id,revision,int(time.time())))
            connection.commit()
            return {"applied":True,"revision":revision}
