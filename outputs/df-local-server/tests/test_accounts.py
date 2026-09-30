from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import tempfile
import unittest

from dfserver.core import Backend, DomainError


ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "dedicated-local-test-password"


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name)/"accounts.sqlite3"
        self.backend = Backend(self.database,ROOT/"definitions.json")

    def assert_error(self, code, function):
        with self.assertRaises(DomainError) as caught:
            function()
        self.assertEqual(caught.exception.code,code)

    def test_local_credentials_persist_and_do_not_duplicate_inventory(self):
        registered = self.backend.register("独立玩家",PASSWORD)
        inventory = self.backend.dispatch(registered["session"],"inventory.list")
        self.backend = Backend(self.database,ROOT/"definitions.json")
        logged = self.backend.login("独立玩家",PASSWORD)
        self.assertEqual(logged["account"],{"username":"独立玩家","provider":"local"})
        self.assertEqual(logged["profile"]["id"],registered["profile"]["id"])
        self.assertEqual(self.backend.dispatch(logged["session"],"inventory.list"),inventory)

    def test_character_name_is_separate_from_local_login_and_persists(self):
        first = self.backend.register("account_one",PASSWORD)
        second = self.backend.register("account_two",PASSWORD)
        self.assertFalse(self.backend.native_identity(first["session"])["game_registered"])
        self.assertTrue(self.backend.validate_game_nick(first["session"],"离线干员")["available"])
        self.assertEqual(self.backend.register_game_nick(first["session"],"离线干员")["game_nick"],"离线干员")
        self.assertFalse(self.backend.validate_game_nick(second["session"],"离线干员")["available"])
        self.assert_error("GAME_NICK_EXISTS",lambda:self.backend.register_game_nick(second["session"],"离线干员"))
        self.assert_error("GAME_PROFILE_EXISTS",lambda:self.backend.register_game_nick(first["session"],"其他名字"))
        self.backend = Backend(self.database,ROOT/"definitions.json")
        logged = self.backend.login("account_one",PASSWORD)
        identity = self.backend.native_identity(logged["session"])
        self.assertEqual((identity["username"],identity["game_nick"],identity["game_registered"]),
                         ("account_one","离线干员",True))
        self.assertTrue(self.backend.dispatch(logged["session"],"inventory.list")["data"]["items"])

    def test_wrong_unknown_and_passwordless_logins_issue_no_sessions(self):
        self.backend.register("player",PASSWORD)
        for username, password in (("player","wrong-password"),("unknown",PASSWORD),("player",None)):
            self.assert_error("UNAUTHORIZED",lambda:self.backend.login(username,password))
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM players").fetchone()[0],1)

    def test_username_normalization_and_concurrent_registration(self):
        def register(_):
            try:
                return self.backend.register("PLAYER",PASSWORD)["profile"]["id"]
            except DomainError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(register,range(2)))
        self.assertEqual(results.count("ACCOUNT_EXISTS"),1)
        self.assert_error("ACCOUNT_EXISTS",lambda:self.backend.register("ｐｌａｙｅｒ",PASSWORD))
        self.assertEqual(self.backend.login("player",PASSWORD)["account"]["username"],"PLAYER")

    def test_password_verifiers_are_salted_and_sessions_are_hashed(self):
        first = self.backend.register("one",PASSWORD)
        self.backend.register("two",PASSWORD)
        with self.backend.connection() as connection:
            rows = connection.execute("SELECT password_salt,password_verifier,password_iterations FROM accounts ORDER BY username_key").fetchall()
            self.assertNotEqual(rows[0][0],rows[1][0])
            self.assertNotEqual(rows[0][1],rows[1][1])
            self.assertEqual(rows[0][2],600000)
            self.assertEqual(len(rows[0][1]),32)
            token = connection.execute("SELECT token_hash FROM sessions WHERE player_id=?",(first["profile"]["id"],)).fetchone()[0]
            self.assertNotEqual(token,first["session"])
            self.assertEqual(token,self.backend._token_hash(first["session"]))
        self.assertNotIn(PASSWORD.encode(),self.database.read_bytes())

    def test_logout_revokes_only_its_session(self):
        one = self.backend.register("player",PASSWORD)
        two = self.backend.login("player",PASSWORD)
        self.backend.logout(one["session"])
        self.assert_error("UNAUTHORIZED",lambda:self.backend.dispatch(one["session"],"hall.get"))
        self.assertEqual(self.backend.dispatch(two["session"],"profile.get")["data"]["id"],one["profile"]["id"])

    def test_password_change_revokes_all_old_sessions_and_preserves_save(self):
        one = self.backend.register("player",PASSWORD)
        two = self.backend.login("player",PASSWORD)
        self.backend.dispatch(one["session"],"quests.accept",{"quest_id":"local_supply"},"accept",0)
        before = self.backend.dispatch(one["session"],"hall.get")
        changed = self.backend.change_password(one["session"],PASSWORD,"replacement-password")
        for old in (one,two):
            self.assert_error("UNAUTHORIZED",lambda:self.backend.dispatch(old["session"],"hall.get"))
        self.assert_error("UNAUTHORIZED",lambda:self.backend.login("player",PASSWORD))
        self.assertEqual(self.backend.dispatch(changed["session"],"hall.get"),before)
        self.assertEqual(self.backend.login("player","replacement-password")["profile"]["id"],one["profile"]["id"])

    def test_invalid_registration_and_wrong_password_change_are_atomic(self):
        for username, password in (("bad name",PASSWORD),("player","short")):
            with self.assertRaises(DomainError):
                self.backend.register(username,password)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM players").fetchone()[0],0)
        valid = self.backend.register("player",PASSWORD)
        self.assert_error("UNAUTHORIZED",lambda:self.backend.change_password(valid["session"],"wrong-password","replacement-password"))
        self.backend.dispatch(valid["session"],"hall.get")
        self.backend.login("player",PASSWORD)

    def test_legacy_passwordless_saves_remain_but_cannot_be_claimed(self):
        with self.backend.connection() as connection:
            connection.execute("INSERT INTO players(id,local_name) VALUES ('legacy-id','legacy')")
            connection.execute("INSERT INTO sessions VALUES (?,?,?)",(self.backend._token_hash("legacy-token"),"legacy-id",4102444800))
            connection.commit()
        self.backend = Backend(self.database,ROOT/"definitions.json")
        self.assert_error("UNAUTHORIZED",lambda:self.backend.dispatch("legacy-token","hall.get"))
        self.assert_error("UNAUTHORIZED",lambda:self.backend.login("legacy",PASSWORD))
        self.assert_error("ACCOUNT_EXISTS",lambda:self.backend.register("legacy",PASSWORD))
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM players WHERE id='legacy-id'").fetchone()[0],1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM sessions WHERE player_id='legacy-id'").fetchone()[0],0)

    def test_failed_starter_grant_rolls_back_account_player_and_session(self):
        definitions = json.loads((ROOT/"definitions.json").read_text(encoding="utf-8"))
        definitions["containers"]["warehouse"] = [1,1]
        definition_path = Path(self.temporary.name)/"small.json"
        definition_path.write_text(json.dumps(definitions),encoding="utf-8")
        backend = Backend(Path(self.temporary.name)/"small.sqlite3",definition_path)
        self.assert_error("WAREHOUSE_FULL",lambda:backend.register("player",PASSWORD))
        with backend.connection() as connection:
            for table in ("accounts","players","sessions","containers","items"):
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0],0)


if __name__ == "__main__":
    unittest.main()
