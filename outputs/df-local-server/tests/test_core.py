from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend, DomainError


ROOT = Path(__file__).resolve().parent.parent


class BackendTests(unittest.TestCase):
    def setUp(self):
        temporary_root = os.environ.get("DF_TEST_TMP")
        if temporary_root:
            Path(temporary_root).mkdir(parents=True,exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.definitions = ROOT/"definitions.json"
        self.backend = Backend(self.path/"save.sqlite3",self.definitions)
        self.login = self.backend.register("test-player","test-password-123")
        self.token = self.login["session"]
        self.player_id = self.login["profile"]["id"]
        self.sequence = 0

    def read(self, operation="hall.get"):
        return self.backend.dispatch(self.token,operation)

    def mutate(self, operation, payload, request_id=None, expected_revision=None):
        self.sequence += 1
        return self.backend.dispatch(self.token,operation,payload,request_id or str(self.sequence),
            self.read()["revision"] if expected_revision is None else expected_revision)

    def item(self, template):
        return next(item for item in self.read()["data"]["inventory"]["items"] if item["template_id"] == template)

    def assert_error(self, code, function):
        with self.assertRaises(DomainError) as result:
            function()
        self.assertEqual(result.exception.code,code)

    def finish_supply(self):
        self.mutate("quests.accept",{"quest_id":"local_supply"})
        self.mutate("quests.submit",{"quest_id":"local_supply","objective_index":0,
            "instance_id":self.item("local_medkit")["id"],"quantity":2})
        self.mutate("quests.complete",{"quest_id":"local_supply"})
        return self.mutate("quests.claim",{"quest_id":"local_supply"})

    def test_restart_persists_and_starter_items_are_not_duplicated(self):
        before = self.read()
        self.backend = Backend(self.path/"save.sqlite3",self.definitions)
        second_login = self.backend.login("test-player","test-password-123")
        self.assertEqual(second_login["profile"]["id"],self.player_id)
        self.assertEqual(self.read(),before)
        self.assertEqual(len(self.read()["data"]["inventory"]["items"]),2)

    def test_move_overlap_and_bounds_do_not_change_save(self):
        before = self.read()
        rifle = self.item("local_rifle")
        self.assert_error("POSITION_OCCUPIED",lambda:self.mutate("inventory.move",{
            "instance_id":rifle["id"],"container":"warehouse","x":0,"y":0}))
        self.assert_error("OUT_OF_BOUNDS",lambda:self.mutate("inventory.move",{
            "instance_id":rifle["id"],"container":"backpack","x":5,"y":3,"rotated":True}))
        self.assertEqual(self.read(),before)

    def test_split_is_atomic_and_retries_do_not_duplicate(self):
        item = self.item("local_medkit")
        payload = {"instance_id":item["id"],"quantity":1,"container":"backpack","x":0,"y":0}
        result = self.mutate("inventory.split",payload,"split",0)
        self.assertEqual(self.backend.dispatch(self.token,"inventory.split",payload,"split",0),result)
        items = self.read()["data"]["inventory"]["items"]
        self.assertEqual(sum(item["quantity"] for item in items if item["template_id"] == "local_medkit"),3)
        self.assertEqual(len(items),3)
        self.assert_error("REQUEST_ID_CONFLICT",lambda:self.backend.dispatch(self.token,"inventory.split",dict(payload,quantity=2),"split",0))

    def test_stack_split_cannot_overlap_source(self):
        before = self.read()
        item = self.item("local_medkit")
        self.assert_error("POSITION_OCCUPIED",lambda:self.mutate("inventory.split",{
            "instance_id":item["id"],"quantity":1,"container":"warehouse","x":item["x"],"y":item["y"]}))
        self.assertEqual(self.read(),before)

    def test_ownership_prevents_cross_player_item_mutation(self):
        another = self.backend.register("another-player","other-password-123")
        self.assert_error("NOT_FOUND",lambda:self.backend.dispatch(another["session"],"inventory.equip",{
            "instance_id":self.item("local_rifle")["id"],"slot":"primary"},"cross-player",0))

    def test_equip_then_move_back_and_reject_wrong_slot(self):
        item = self.item("local_rifle")
        self.assert_error("INVALID_EQUIPMENT",lambda:self.mutate("inventory.equip",{"instance_id":item["id"],"slot":"helmet"}))
        self.mutate("inventory.equip",{"instance_id":item["id"],"slot":"primary"})
        self.assertEqual(self.item("local_rifle")["equipped_slot"],"primary")
        self.mutate("inventory.move",{"instance_id":item["id"],"container":"backpack","x":0,"y":0})
        self.assertIsNone(self.item("local_rifle")["equipped_slot"])

    def test_quest_prerequisite_and_early_completion_are_enforced(self):
        self.assert_error("QUEST_LOCKED",lambda:self.mutate("quests.accept",{"quest_id":"local_training"}))
        self.mutate("quests.accept",{"quest_id":"local_supply"})
        before = self.read()
        self.assert_error("OBJECTIVES_INCOMPLETE",lambda:self.mutate("quests.complete",{"quest_id":"local_supply"}))
        self.assert_error("INVALID_QUEST_STATE",lambda:self.mutate("quests.claim",{"quest_id":"local_supply"}))
        self.assertEqual(self.read(),before)

    def test_submit_complete_reward_is_persistent_and_single_use(self):
        self.mutate("quests.accept",{"quest_id":"local_supply"})
        payload = {"quest_id":"local_supply","objective_index":0,
            "instance_id":self.item("local_medkit")["id"],"quantity":2}
        revision = self.read()["revision"]
        submit = self.mutate("quests.submit",payload,"submission",revision)
        self.assertEqual(self.backend.dispatch(self.token,"quests.submit",payload,"submission",revision),submit)
        self.assertEqual(self.item("local_medkit")["quantity"],1)
        self.mutate("quests.complete",{"quest_id":"local_supply"})
        revision = self.read()["revision"]
        reward = self.mutate("quests.claim",{"quest_id":"local_supply"},"reward",revision)
        self.assertEqual(reward["data"]["profile"]["revision"],reward["revision"])
        self.backend = Backend(self.path/"save.sqlite3",self.definitions)
        self.assertEqual(self.backend.dispatch(self.token,"quests.claim",{"quest_id":"local_supply"},"reward",revision),reward)
        self.assertEqual(self.read()["data"]["profile"]["money"],1000)
        self.assertEqual(self.item("local_ammo")["quantity"],30)
        self.assert_error("INVALID_QUEST_STATE",lambda:self.mutate("quests.claim",{"quest_id":"local_supply"}))

    def test_untrusted_client_cannot_report_kills(self):
        self.assert_error("UNSUPPORTED_OPERATION",lambda:self.backend.dispatch(self.token,"trusted.event",{"kind":"kill"}))

    def test_trusted_event_deduplication_and_capped_progress(self):
        self.finish_supply()
        self.mutate("quests.accept",{"quest_id":"local_training"})
        event = self.backend.record_event(self.player_id,"battle-event-1","kill","local_bot",5)
        self.assertTrue(event["applied"])
        self.backend = Backend(self.path/"save.sqlite3",self.definitions)
        self.assertFalse(self.backend.record_event(self.player_id,"battle-event-1","kill","local_bot",5)["applied"])
        self.assert_error("EVENT_ID_CONFLICT",lambda:self.backend.record_event(self.player_id,"battle-event-1","kill","local_bot",1))
        self.assertEqual(self.read()["data"]["quests"][1]["progress"],[3])
        self.mutate("quests.complete",{"quest_id":"local_training"})
        self.mutate("quests.claim",{"quest_id":"local_training"})
        self.assertEqual(self.read()["data"]["profile"]["money"],3000)

    def test_concurrent_retries_produce_one_committed_change(self):
        def request(_):
            return self.backend.dispatch(self.token,"quests.accept",{"quest_id":"local_supply"},"same-id",0)
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(request,range(4)))
        self.assertTrue(all(value == responses[0] for value in responses))
        self.assertEqual(self.read()["revision"],1)

    def test_competing_revisions_allow_one_winner(self):
        item = self.item("local_rifle")
        def request(index):
            try:
                return self.backend.dispatch(self.token,"inventory.move",{"instance_id":item["id"],
                    "container":"backpack","x":index,"y":0},str(index),0)["revision"]
            except DomainError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(request,[0,2]))
        self.assertCountEqual(result,[1,"STALE_REVISION"])

    def test_reward_overflow_rolls_back_every_side_effect(self):
        definitions = json.loads(self.definitions.read_text(encoding="utf-8"))
        definitions["containers"]["warehouse"] = [3,1]
        definitions["quests"] = {"full_reward": {
            "objectives":[{"kind":"kill","target":"local_bot","count":1}],
            "reward":{"money":999,"xp":99,"items":[{"template_id":"local_ammo","quantity":1}]}}}
        definition_path = self.path/"tight.json"
        definition_path.write_text(json.dumps(definitions),encoding="utf-8")
        self.backend = Backend(self.path/"tight.sqlite3",definition_path)
        self.login = self.backend.register("full","test-password-123")
        self.token,self.player_id = self.login["session"],self.login["profile"]["id"]
        self.mutate("quests.accept",{"quest_id":"full_reward"})
        self.backend.record_event(self.player_id,"kill-1","kill","local_bot",1)
        self.mutate("quests.complete",{"quest_id":"full_reward"})
        before = self.read()
        self.assert_error("WAREHOUSE_FULL",lambda:self.mutate("quests.claim",{"quest_id":"full_reward"}))
        self.assertEqual(self.read(),before)

    def test_changed_definition_rejects_existing_save(self):
        definitions = json.loads(self.definitions.read_text(encoding="utf-8"))
        definitions["items"]["local_medkit"]["width"] = 2
        changed = self.path/"changed.json"
        changed.write_text(json.dumps(definitions),encoding="utf-8")
        self.assert_error("DEFINITIONS_CHANGED",lambda:Backend(self.path/"save.sqlite3",changed))

    def test_invalid_argument_and_expired_session_do_not_mutate(self):
        self.assert_error("INVALID_ARGUMENT",lambda:self.mutate("inventory.move",{
            "instance_id":self.item("local_rifle")["id"],"container":"backpack","x":True,"y":0}))
        with self.backend.connection() as connection:
            connection.execute("UPDATE sessions SET expires=0")
            connection.commit()
        self.assert_error("UNAUTHORIZED",lambda:self.read())


if __name__ == "__main__":
    unittest.main()
