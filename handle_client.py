class handle_client:
    def __init__(self, client_socket, protocol):
        self.client_socket = client_socket
    
        #handles clients req and res
    def handle_request (self):
        while True:
            parsed_req = protocol.recv_request(self.client_socket)
            # print(parsed_req)
            if parsed_req == b"": #ends client connection after client disconnected
                print("Client Disconnected")
                self.client_socket.close()
                break
            if self.protocol.check_request(parsed_req):     #handles GET requests for now
                res = self.protocol.build_response(self.handle_response(parsed_req[0][0:2], parsed_req[2]))
                self.client_socket.send(res)
            else: #Unknown request or request
                self.protocol.build_response((self.STATUS_TABLE[500].encode(), self.protocol.CONTENT_TYPE["txt"], self.STATUS_TABLE[500]))
        
        self.client_socket.close()
    
    def handle_authentication ():

    def handle_register ():

    