import SimpleHTTPServer
import SocketServer
import threading
import time
import urlparse

from common.tools.converters import BytesToHex


class TimeLeakingWebServer(object):
    
    ADDRESS = '127.0.0.1'
    PORT = 8080
    TIMING_LEAK = 0.015
    
    def __init__(self, message, hmac, timing_leak=None):
        self.thread = threading.Thread(target=self._run)
        self.message = message
        self.hmac = BytesToHex(hmac).value()
        self.timing_leak = timing_leak if timing_leak is not None\
                           else self.TIMING_LEAK
        SocketServer.TCPServer.allow_reuse_address = True
        self.server = SocketServer.TCPServer((self.ADDRESS, self.PORT),
                                             self._request_handler())
        
    def _request_handler(self):
        server = self
        
        class RequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
            
            def do_GET(self):
                query_string = self.path.split('?')[1]
                parsed_query_string = urlparse.parse_qs(query_string)
                signature = parsed_query_string['signature'][0]
                response_code = 200 if self._validate_signature(signature)\
                                else 500
                self.send_response(response_code)
                
            def _validate_signature(self, signature):
                for i in range(0, len(server.hmac), 2):
                    if signature[i:i+2] != server.hmac[i:i+2]:
                        return False
                    time.sleep(server.timing_leak)
                return True
                
            def log_message(self, *args, **kwargs):
                pass
        
        return RequestHandler
        
    def _run(self):
        self.server.serve_forever()
        
    def start(self):
        self.thread.start()
        
    def stop(self):
        self.server.shutdown()
        self.thread.join()
        
    def __enter__(self, *args, **kwargs):
        self.start()
        return self
        
    def __exit__(self, *args, **kwargs):
        self.stop()