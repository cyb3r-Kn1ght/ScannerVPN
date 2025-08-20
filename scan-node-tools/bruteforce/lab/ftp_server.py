from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
a=DummyAuthorizer(); a.add_user("dev","Summer2025!","/tmp",perm="elr")
h=FTPHandler; h.authorizer=a; h.passive_ports=range(21000,21006)
FTPServer(("0.0.0.0",2121),h).serve_forever()
