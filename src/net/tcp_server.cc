#include "net/tcp_server.h"


namespace tsc::tcp {
TcpServer::TcpServer(u16 port, Node* node) : port_(port), node_(node) {}

TcpServer::~TcpServer() { Stop(); }

bool TcpServer::Start() {
  server_socket_ = socket()
}

}  // namespace tsc::tcp