from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import time
import threading
import re
from pathlib import Path
import queue

from settings import FITBIT_PATH_PTRN


FITBIT_CODE_STATE_PTRN = re.compile(r"\?code=(\S+)&state=(\S)")


class CustomHTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.q = server.q  # queue
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain; charset=utf-8")
        self.end_headers()

        res_message = "No data"
        request_path = Path(self.path)
        if request_path.parent == FITBIT_PATH_PTRN:
            res_message = "is fitbit path"
            if FITBIT_CODE_STATE_PTRN.match(request_path.name):
                code, state = FITBIT_CODE_STATE_PTRN.sub(
                    r"\1&\2", request_path.name
                ).split("&")
                res_message = f"code = {code}, state = {state}"
                code_and_state = {
                    "code": code,
                    "state": state,
                }
                if self.q:
                    # Put item
                    self.q.put(code_and_state)

        # Write response message for body
        self.wfile.write(res_message.encode(encoding="utf-8"))


class MyHttpServer:
    def __init__(
        self,
        q: queue.Queue,
        server_name: str = "localhost",
        server_port: int = 80,
    ):
        server_address = (server_name, server_port)
        self.httpd = ThreadingHTTPServer(
            server_address,
            CustomHTTPRequestHandler,
        )
        self.httpd.q = q
        address = f"http://{server_name}"
        if server_port != 80:
            address += f":{server_port}"
        self.address = f"{address}/"

    def stop_server(self, sleep_time: int = 4):
        print(f"Stop after {sleep_time} s")
        time.sleep(sleep_time)
        print("Stop server")
        self.httpd.shutdown()
        print("Server stopped")

    def start_server(self):
        print("Run server")
        time.sleep(1)
        server_thread = threading.Thread(target=self.httpd.serve_forever)
        server_thread.start()


if __name__ == "__main__":
    q = queue.Queue(1)
    my_http_server = MyHttpServer(q)
    # Print URL for test
    print(f"Open {my_http_server.address}/?code=hoge&state=fuga")

    # Start server
    my_http_server.start_server()

    for i in range(20):
        # Print time
        print(f"\rtime = {i+1}", end="")
        if not q.empty():
            # Get q item
            code_and_state = q.get()
            print(code_and_state)
            # Stop server
            my_http_server.stop_server(sleep_time=4)
            break
        time.sleep(1)
    else:
        # Stop server
        my_http_server.stop_server(sleep_time=4)
