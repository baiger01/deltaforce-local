import base64
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from dfserver.core import Backend, DomainError
from dfserver.http_api import create_server
from dfserver.protobuf_codec import ProtobufCodec
from dfserver.zone_discovery import GET_ZONE_PATH


ROOT=Path(__file__).resolve().parent.parent


class ApiTests(unittest.TestCase):
    def setUp(self):
        temporary_root=os.environ.get("DF_TEST_TMP")
        if temporary_root:
            Path(temporary_root).mkdir(parents=True,exist_ok=True)
        self.temporary=tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.backend=Backend(Path(self.temporary.name)/"save.sqlite3",ROOT/"definitions.json")
        self.codec=ProtobufCodec(ROOT/"protocol/recovered_telemetry.pb")
        self.server=create_server(self.backend,self.codec,port=0)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={"poll_interval":0.01},daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.url=f"http://127.0.0.1:{self.server.server_port}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def call(self,path,body=None,token=None):
        headers={"Content-Type":"application/json"}
        if token:
            headers["Authorization"]="Bearer "+token
        request=Request(self.url+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
        try:
            response=urlopen(request,timeout=3)
        except HTTPError as error:
            response=error
        with response:
            return response.status,json.load(response)

    def test_http_login_read_and_mutation(self):
        status,health=self.call("/healthz")
        self.assertEqual(status,200)
        self.assertFalse(health["game_compatibility_verified"])
        status,registered=self.call("/api/local/register",{"username":"http-player","password":"http-test-password"})
        self.assertEqual(status,200)
        status,login=self.call("/api/local/login",{"username":"http-player","password":"http-test-password"})
        self.assertEqual(status,200)
        self.assertEqual(login["result"]["profile"]["id"],registered["result"]["profile"]["id"])
        token=login["result"]["session"]
        status,read=self.call("/api/local/dispatch",{"operation":"hall.get"},token)
        self.assertEqual(status,200)
        self.assertEqual(read["result"]["revision"],0)
        status,result=self.call("/api/local/dispatch",{"operation":"quests.accept",
            "payload":{"quest_id":"local_supply"},"request_id":"http-accept","expected_revision":0},token)
        self.assertEqual(status,200)
        self.assertEqual(result["result"]["revision"],1)
        self.assertFalse(result["game_compatibility_verified"])

    def test_http_missing_session_and_unready_gateway_fail(self):
        status,result=self.call("/api/local/dispatch",{"operation":"hall.get"})
        self.assertEqual(status,401)
        self.assertEqual(result["error"]["code"],"UNAUTHORIZED")
        status,result=self.call("/api/protobuf/dispatch",{"message":"pb.CSAccountLoginReq"})
        self.assertEqual(status,409)
        self.assertEqual(result["error"]["code"],"GAME_GATEWAY_NOT_READY")

    def test_game_profile_name_requires_an_explicit_authenticated_request(self):
        _,registered=self.call("/api/local/register",{"username":"own-character",
                                                    "password":"local-test-password"})
        token=registered["result"]["session"]
        status,profile=self.call("/api/local/game-profile",{},token)
        self.assertEqual(status,200)
        self.assertFalse(profile["result"]["game_registered"])
        status,_=self.call("/api/local/register-game-nick",{"game_nick":"自选角色"})
        self.assertEqual(status,401)
        status,created=self.call("/api/local/register-game-nick",{"game_nick":"自选角色"},token)
        self.assertEqual(status,200)
        self.assertEqual(created["result"]["game_nick"],"自选角色")
        status,profile=self.call("/api/local/game-profile",{},token)
        self.assertTrue(profile["result"]["game_registered"])
        self.assertEqual(profile["result"]["game_nick"],"自选角色")

    def test_frontend_assets_and_catalog_are_served_without_private_files(self):
        for path, content_type in (("/","text/html"),("/ui/app.js","text/javascript"),("/ui/style.css","text/css")):
            with urlopen(self.url+path,timeout=3) as response:
                self.assertEqual(response.status,200)
                self.assertIn(content_type,response.headers["Content-Type"])
                self.assertTrue(response.read())
                self.assertEqual(response.headers["X-Content-Type-Options"],"nosniff")
        for path in ("/data/local.sqlite3","/ui/../../data/local.sqlite3","/ui/%2e%2e/core.py","/ui/app.js/../core.py"):
            status,result=self.call(path)
            self.assertEqual(status,404)
        status,catalog=self.call("/api/local/catalog")
        self.assertEqual(status,200)
        self.assertEqual(catalog["result"]["items"],self.backend.definitions["items"])
        self.assertNotIn("starter_items",catalog["result"])

    def test_browser_origin_cannot_mutate_local_account_or_save(self):
        status,registered=self.call("/api/local/register",{"username":"browser-player","password":"browser-test-password"})
        token=registered["result"]["session"]
        body={"operation":"quests.accept","payload":{"quest_id":"local_supply"},"request_id":"origin-check","expected_revision":0}
        for origin in ("https://unrelated.example","null"):
            request=Request(self.url+"/api/local/dispatch",data=json.dumps(body).encode(),
                            headers={"Content-Type":"application/json","Origin":origin,"Authorization":"Bearer "+token})
            with self.assertRaises(HTTPError) as exception:
                urlopen(request,timeout=3)
            with exception.exception as response:
                self.assertEqual(response.status,403)
                self.assertEqual(json.load(response)["error"]["code"],"INVALID_ORIGIN")
        self.assertEqual(self.backend.dispatch(token,"hall.get")["revision"],0)
        request=Request(self.url+"/api/local/dispatch",data=json.dumps(body).encode(),
                        headers={"Content-Type":"application/json","Origin":self.url,"Authorization":"Bearer "+token})
        with urlopen(request,timeout=3) as response:
            self.assertEqual(json.load(response)["result"]["revision"],1)

    def test_foreign_host_is_rejected(self):
        request=Request(self.url+"/healthz",headers={"Host":"unrelated.example"})
        with self.assertRaises(HTTPError) as exception:
            urlopen(request,timeout=3)
        with exception.exception as response:
            self.assertEqual(response.status,403)
            self.assertEqual(json.load(response)["error"]["code"],"INVALID_HOST")

    def test_independent_account_http_lifecycle(self):
        credentials = {"username":"account-http","password":"local-account-password"}
        status, registered = self.call("/api/local/register",credentials)
        self.assertEqual(status,200)
        first = registered["result"]["session"]
        status, duplicate = self.call("/api/local/register",credentials)
        self.assertEqual(status,409)
        self.assertEqual(duplicate["error"]["code"],"ACCOUNT_EXISTS")
        status, wrong = self.call("/api/local/login",dict(credentials,password="wrong-password"))
        self.assertEqual(status,401)
        status, old = self.call("/api/local/login",{"local_name":"account-http"})
        self.assertEqual(status,401)
        status, changed = self.call("/api/local/change-password",{
            "current_password":credentials["password"],"new_password":"replacement-password"},first)
        self.assertEqual(status,200)
        second = changed["result"]["session"]
        status, _ = self.call("/api/local/dispatch",{"operation":"hall.get"},first)
        self.assertEqual(status,401)
        status, _ = self.call("/api/local/logout",{},second)
        self.assertEqual(status,200)
        status, _ = self.call("/api/local/dispatch",{"operation":"hall.get"},second)
        self.assertEqual(status,401)
        status, logged = self.call("/api/local/login",dict(credentials,password="replacement-password"))
        self.assertEqual(status,200)
        self.assertEqual(logged["result"]["account"]["provider"],"local")
        self.assertEqual(logged["result"]["profile"]["id"],registered["result"]["profile"]["id"])

    def test_recovered_schema_encode_decode_and_http(self):
        if self.codec.pool is None:
            self.skipTest("Optional protobuf library is not installed")
        fields={"name":"codec-check","body":base64.b64encode(b"test").decode()}
        payload=self.codec.encode("pb.NetNotice",fields)
        self.assertEqual(self.codec.decode("pb.NetNotice",payload),fields)
        status,result=self.call("/api/protobuf/decode",{"message":"pb.NetNotice",
            "payload_base64":base64.b64encode(payload).decode()})
        self.assertEqual(status,200)
        self.assertEqual(result["result"],fields)

    def test_unknown_business_schema_is_not_fabricated(self):
        if self.codec.pool is None:
            self.skipTest("Optional protobuf library is not installed")
        status,result=self.call("/api/protobuf/decode",{"message":"pb.CSDepositGetPropsReq","payload_base64":""})
        self.assertEqual(status,409)
        self.assertEqual(result["error"]["code"],"UNKNOWN_MESSAGE_SCHEMA")
        with self.assertRaises(DomainError) as exception:
            self.codec.encode("pb.NetNotice",{"invented_field":1})
        self.assertEqual(exception.exception.code,"INVALID_PROTOBUF_FIELDS")

    def test_invalid_request_is_rejected(self):
        status,result=self.call("/api/protobuf/decode",{"message":"pb.NetNotice","payload_base64":"!!!"})
        self.assertEqual(status,400)
        self.assertEqual(result["error"]["code"],"INVALID_REQUEST")
        with self.assertRaises(ValueError):
            create_server(self.backend,self.codec,host="0.0.0.0",port=0)

    def test_launcher_zone_reply_uses_native_shape_and_nested_address_json(self):
        status, reply = self.call(GET_ZONE_PATH, {"game_id": "2001918", "from_src": "launcher"})
        self.assertEqual(status, 200)
        self.assertEqual(set(reply), {"result", "zone_info", "zone_support_role_query"})
        self.assertEqual(reply["result"]["error_code"], 0)
        self.assertEqual([z["zone_id"] for z in reply["zone_info"]], ["101", "102"])
        for zone in reply["zone_info"]:
            self.assertEqual(json.loads(zone["server_ips"]), ["127.0.0.1:65010"])
            self.assertEqual(json.loads(zone["bind_branch"]), [1])
            self.assertEqual(json.loads(zone["metadata"])["zone_id"], zone["zone_id"])
            self.assertEqual(zone["zone_name_en_us"], "df_local_loopback")
        status, state = self.call("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(state["zone_discovery"]["requests_total"], 1)
        self.assertFalse(state["game_compatibility_verified"])
        status, rejection = self.call("/api/protobuf/dispatch", {"message": "pb.CSAccountLoginReq"})
        self.assertEqual(status, 409)
        self.assertEqual(rejection["error"]["code"], "GAME_GATEWAY_NOT_READY")

    def test_zone_discovery_rejects_other_game_and_source(self):
        for body in ({"game_id": "other", "from_src": "launcher"}, {"game_id": "2001918"}):
            status, reply = self.call(GET_ZONE_PATH, body)
            self.assertEqual(status, 400)
            self.assertEqual(reply["error"]["code"], "INVALID_ZONE_REQUEST")
        self.assertEqual(self.server.zone_discovery.status()["requests_total"], 0)


if __name__ == "__main__":
    unittest.main()
