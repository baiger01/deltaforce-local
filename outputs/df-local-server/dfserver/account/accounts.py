"""Manage independent local accounts without putting passwords in arguments."""
import argparse
import getpass
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description="Independent local account management; original game login is not connected")
    parser.add_argument("action", nargs="?", choices=("register", "login", "password"))
    parser.add_argument("username", nargs="?")
    parser.add_argument("--port", type=int, default=8877)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    action = args.action or input("操作 register / login / password: ").strip()
    if action not in ("register", "login", "password"):
        parser.error("choose register, login or password")
    username = args.username or input("本地用户名: ").strip()
    password = getpass.getpass("本地密码: ")

    def call(path, body, token=None):
        headers = {"Content-Type":"application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = Request(f"http://127.0.0.1:{args.port}{path}",
                          data=json.dumps(body).encode("utf-8"),headers=headers)
        with urlopen(request,timeout=15) as response:
            return json.load(response)["result"]

    try:
        if action == "register":
            if password != getpass.getpass("再次输入本地密码: "):
                print("两次密码不一致。")
                return 1
            result = call("/api/local/register",{"username":username,"password":password})
        else:
            result = call("/api/local/login",{"username":username,"password":password})
        if action == "password":
            new = getpass.getpass("新密码: ")
            if new != getpass.getpass("再次输入新密码: "):
                call("/api/local/logout",{},result["session"])
                print("两次新密码不一致。")
                return 1
            result = call("/api/local/change-password",{"current_password":password,"new_password":new},result["session"])
            del new
        del password
        call("/api/local/logout",{},result["session"])
        print(json.dumps({"action":action,"account":result["account"],
                          "local_account_verified":True,"original_game_login_connected":False},ensure_ascii=False,indent=2))
        return 0
    except HTTPError as error:
        # Error responses contain no credential values. Print a fixed error code only.
        try:
            code = json.load(error).get("error",{}).get("code","REQUEST_FAILED")
        except (ValueError, OSError):
            code = "REQUEST_FAILED"
        print("本地账号操作失败: " + str(code))
        return 1
    except (URLError, TimeoutError, OSError):
        print("无法连接本地服务，请先运行 start.cmd。")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
