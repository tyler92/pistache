/*
 * SPDX-FileCopyrightText: 2021 David Korczynski
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pistache/http.h>
#include <pistache/router.h>

using namespace Pistache;

void ignoreExceptions(const std::function<void()>& func)
{
    try
    {
        func();
    }
    catch (...)
    {
    }
}

void parseHttpHeader(const std::string& name, const std::string& input)
{
    auto header = Pistache::Http::Header::Registry::instance().makeHeader(name);
    ignoreExceptions([&] { header->parse(input); });
    ignoreExceptions([&] { header->parseRaw(input.data(), input.size()); });

    std::stringstream oss;
    header->write(oss);
}

void parseAuthorizationHeader(const std::string& input)
{
    Pistache::Http::Header::Authorization header;
    ignoreExceptions([&] { header.parse(input); });
    ignoreExceptions([&] { header.getMethod(); });
    ignoreExceptions(
        [&] {
            const auto user     = header.getBasicUser();
            const auto password = header.getBasicPassword();
            header.setBasicUserPassword(user, password);
        });
}

void fuzz_headers(const std::string& input)
{
    for (const auto& header : Pistache::Http::Header::Registry::instance().headersList())
    {
        parseHttpHeader(header, input);
    }

    // Special cases
    parseAuthorizationHeader(input);
}

void fuzz_cookies(const std::string& input)
{
    Pistache::Http::CookieJar cookie_jar;
    ignoreExceptions([&] { Pistache::Http::Cookie::fromString(input); });
    ignoreExceptions([&] { cookie_jar.addFromRaw(input.data(), input.size()); });
}

void fuzz_request_parser(const std::string& input)
{
    constexpr size_t maxDataSize = 4096;
    Pistache::Http::RequestParser rparser(maxDataSize);

    if (rparser.feed(input.data(), input.size()))
    {
        auto state = Pistache::Http::Private::State::Done;
        ignoreExceptions([&] { state = rparser.parse(); });

        if (state == Pistache::Http::Private::State::Again)
            ignoreExceptions([&] { rparser.parse(); });
    }
}

void fuzz_router(const std::string& input)
{
    std::string path_input;
    std::stringstream input_stream(input);
    Pistache::Rest::SegmentTreeNode tree;

    while (std::getline(input_stream, path_input, '\n'))
    {
        if (path_input.size() < 2)
            continue;

        const int test_case = path_input.back();
        path_input.pop_back();

        const auto sanitized = Pistache::Rest::SegmentTreeNode::sanitizeResource(path_input);
        std::shared_ptr<char> ptr(new char[sanitized.length()], std::default_delete<char[]>());
        memcpy(ptr.get(), sanitized.data(), sanitized.length());
        const std::string_view path { ptr.get(), sanitized.length() };

        switch (test_case)
        {
        case 'A':
            ignoreExceptions([&] {
                Pistache::Rest::Route::Handler handler = [](auto...) { return Pistache::Rest::Route::Result::Ok; };
                std::shared_ptr<char> ptr(new char[sanitized.length()], std::default_delete<char[]>());
                memcpy(ptr.get(), sanitized.data(), sanitized.length());
                const std::string_view path { ptr.get(), sanitized.length() };
                tree.addRoute(path, handler, ptr);
            });
            break;
        case 'R':
            ignoreExceptions([&] { tree.removeRoute(path); });
            break;
        case 'F':
            ignoreExceptions([&] { tree.findRoute(path); });
            break;
        }
    }
}

void fuzz_other(const std::string& input)
{
    // URI parsing
    Http::Uri::Query query1;
    query1.add(input, input);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return -1;

    const uint8_t type = data[0];
    const std::string input(reinterpret_cast<const char*>(data + 1), size - 1);

    switch (type)
    {
    case 'H':
        fuzz_headers(input);
        break;
    case 'C':
        fuzz_cookies(input);
        break;
    case 'R':
        fuzz_request_parser(input);
        break;
    case 'S':
        fuzz_router(input);
        break;
    case 'O':
        fuzz_other(input);
        break;
    }

    return 0;
}
