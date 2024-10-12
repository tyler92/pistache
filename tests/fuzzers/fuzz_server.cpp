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
#include <pistache/serializer/rapidjson.h>

using namespace Pistache;

class FuzzHandler : public Http::Handler
{
  public:
    HTTP_PROTOTYPE(FuzzHandler)

    void onRequest(const Http::Request& request, Http::ResponseWriter writer) override
    {
        std::string requestAddress = request.address().host();
        writer.send(Http::Code::Ok, requestAddress);
    }

    void ping(const Rest::Request&, Http::ResponseWriter writer)
    {
        writer.send(Http::Code::Ok, "pong");
    }
};

void sendPingRequest(const Address& address)
{
    Http::Experimental::Client httpClient;
    httpClient.init();
    auto response = httpClient.get(address.host() + ":" + address.port().toString() + "/ping").send();
    Async::Barrier<Http::Response> barrier(response);
    barrier.wait_for(std::chrono::seconds(1));
    httpClient.shutdown();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Initialize dummy routes
    FuzzHandler handler;
    Rest::Description desc("SwaggerEndpoint API", "1.0");
    desc.route("/api", Http::Method::Get)
        .bind(&FuzzHandler::onRequest, &handler)
        .consumes(MIME(Text, Json))
        .parameter<int>("id", "ID")
        .response(Http::Code::Ok, "Ok")
        .produces(MIME(Text, Json));

    Rest::Router router = Rest::Router::fromDescription(desc);
    Rest::Routes::Get(router, "/ping", Rest::Routes::bind(&FuzzHandler::ping, &handler));
    Rest::Routes::Post(router, "/ping", Rest::Routes::bind(&FuzzHandler::ping, &handler));
    Rest::Routes::Head(router, "/ping", Rest::Routes::bind(&FuzzHandler::ping, &handler));
    Rest::Routes::Patch(router, "/ping", Rest::Routes::bind(&FuzzHandler::ping, &handler));
    Rest::Routes::Delete(router, "/ping", Rest::Routes::bind(&FuzzHandler::ping, &handler));

    Rest::Swagger swagger(desc);
    swagger.apiPath("/doc")
        .uiPath("status")
        .uiDirectory("/proc/self")
        .serializer(&Rest::Serializer::rapidJson)
        .install(router);

    // Initialize server
    const Address address(IP::loopback(), Port(0));
    Http::Endpoint server(address);
    server.setHandler(router.handler());

    const auto flags = Tcp::Options::ReuseAddr | Tcp::Options::NoDelay;
    const auto server_opts = Http::Endpoint::options().flags(flags);
    server.init(server_opts);
    server.serveThreaded();

    // Main fuzzing target: send raw message via TCP
    auto tcpClient = std::make_unique<TcpClient>();
    tcpClient->connect(Address(address.host(), server.getPort()));
    tcpClient->send(std::string(reinterpret_cast<const char*>(data), size));

    // A deterministic GET request to make sure the previous request consumed
    sendPingRequest(Address(address.host(), server.getPort()));

    tcpClient.reset();
    server.shutdown();
    return 0;
}
