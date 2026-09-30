"""Exercise the implemented local backend through HTTP; this does not launch the game."""
import argparse
import json
import secrets
from pathlib import Path
import uuid
from urllib.request import Request, urlopen


def main():
    parser=argparse.ArgumentParser(description="Development backend verification")
    parser.add_argument("--port",type=int,default=8877)
    parser.add_argument("--receipt",type=Path,help="Save non-secret verification state for restart checks")
    arguments=parser.parse_args()
    base=f"http://127.0.0.1:{arguments.port}"
    token=None
    def call(path,body=None):
        headers={"Content-Type":"application/json"}
        if token:
            headers["Authorization"]="Bearer "+token
        request=Request(base+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
        with urlopen(request,timeout=5) as response:
            value=json.load(response)
        assert value["ok"] and value["game_compatibility_verified"] is False
        return value.get("result",value)
    health=call("/healthz")
    local_name="verification-"+uuid.uuid4().hex[:10]
    password=secrets.token_urlsafe(24)
    registered=call("/api/local/register",{"username":local_name,"password":password})
    token=registered["session"]
    call("/api/local/logout",{})
    token=None
    login=call("/api/local/login",{"username":local_name,"password":password})
    del password
    token=login["session"]
    def read():
        return call("/api/local/dispatch",{"operation":"hall.get"})
    def mutate(operation,payload,request_id=None,revision=None):
        request={"operation":operation,"payload":payload,"request_id":request_id or uuid.uuid4().hex,
                 "expected_revision":read()["revision"] if revision is None else revision}
        return call("/api/local/dispatch",request)
    item=next(item for item in read()["data"]["inventory"]["items"] if item["template_id"]=="local_medkit")
    mutate("quests.accept",{"quest_id":"local_supply"})
    mutate("quests.submit",{"quest_id":"local_supply","objective_index":0,"instance_id":item["id"],"quantity":2})
    mutate("quests.complete",{"quest_id":"local_supply"})
    revision=read()["revision"]
    reward=mutate("quests.claim",{"quest_id":"local_supply"},"reward-check",revision)
    replay=mutate("quests.claim",{"quest_id":"local_supply"},"reward-check",revision)
    assert replay==reward
    hall=read()["data"]
    assert hall["profile"]["money"]==1000 and hall["profile"]["xp"]==100
    assert any(item["template_id"]=="local_ammo" and item["quantity"]==30 for item in hall["inventory"]["items"])
    if arguments.receipt:
        arguments.receipt.parent.mkdir(parents=True,exist_ok=True)
        arguments.receipt.write_text(json.dumps({"local_name":local_name,"profile":hall["profile"],
            "items":hall["inventory"]["items"]},ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({"local_backend":"passed","operations":"register -> logout -> password login -> submit -> complete -> claim -> retry",
                      "revision":hall["profile"]["revision"],"money":hall["profile"]["money"],
                      "reward_replay":"no duplication","original_game_connected":False},indent=2))


if __name__=="__main__":
    main()
