/*
 * SPDX-FileCopyrightText: 2024 Mikhail Khachayants
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tcp_client.h"
#include <pistache/client.h>
#include <pistache/description.h>
#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>

using namespace Pistache;

class FuzzHandler
{
public:
    void echo(const Rest::Request& req, Http::ResponseWriter writer)
    {
        writer.send(Http::Code::Ok, req.body());
    }
};

void sendRequest(const Address& address)
{
    Http::Experimental::Client httpClient;
    httpClient.init(Http::Experimental::Client::Options().maxConnectionsPerHost(1));
    auto response = httpClient.get(address.host() + ":" + address.port().toString() + "/echo").send();
    Async::Barrier<Http::Response> barrier(response);
    barrier.wait_for(std::chrono::seconds(1));
    httpClient.shutdown();
}

Rest::Router setupRouter(FuzzHandler& handler)
{
    Rest::Router router;
    Rest::Routes::Get(router, "/echo", Rest::Routes::bind(&FuzzHandler::echo, &handler));
    Rest::Routes::Post(router, "/echo", Rest::Routes::bind(&FuzzHandler::echo, &handler));
    Rest::Routes::Head(router, "/echo", Rest::Routes::bind(&FuzzHandler::echo, &handler));
    Rest::Routes::Patch(router, "/echo", Rest::Routes::bind(&FuzzHandler::echo, &handler));
    Rest::Routes::Delete(router, "/echo", Rest::Routes::bind(&FuzzHandler::echo, &handler));
    return router;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Initialize routes
    FuzzHandler handler;
    Rest::Router router = setupRouter(handler);

    // Initialize server
    Http::Endpoint server(Address(IP::loopback(), Port(0)));
    server.init(Http::Endpoint::options().flags(Tcp::Options::ReuseAddr | Tcp::Options::NoDelay));
    server.setHandler(router.handler());
    server.serveThreaded();

    // Main fuzzing target: send raw message via TCP
    TcpClient tcpClient;
    tcpClient.connect(Address(IP::loopback(), server.getPort()));
    tcpClient.send(reinterpret_cast<const char*>(data), size);

    // A deterministic GET request to make sure the previous request was consumed
    sendRequest(Address(IP::loopback(), server.getPort()));

    server.shutdown();
    return 0;
}
