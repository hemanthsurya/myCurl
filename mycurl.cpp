#include <getopt.h>
#include <iostream>
#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>

namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

struct Url {
    std::string scheme, host, port, target;
};

static Url parse_url(const std::string& u) {
    Url r;
    auto p = u.find("://");
    if (p == std::string::npos)
        throw std::runtime_error("Bad URL");

    r.scheme = u.substr(0, p);
    std::string rest = u.substr(p + 3);

    auto slash = rest.find('/');
    std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    r.target = (slash == std::string::npos) ? "/" : rest.substr(slash);

    auto colon = hostport.find(':');
    if (colon == std::string::npos) {
        r.host = hostport;
        r.port = (r.scheme == "https") ? "443" : "80";
    } else {
        r.host = hostport.substr(0, colon);
        r.port = hostport.substr(colon + 1);
    }
    return r;
}

static bool get_method(const std::string& url) {
    Url u = parse_url(url);
    net::io_context ioc;
    tcp::resolver resolver(ioc);
    tcp::socket socket(ioc);

    auto results = resolver.resolve(u.host, u.port);
    net::connect(socket, results);

    http::request<http::empty_body> req{http::verb::get, u.target, 11};
    req.set(http::field::host, u.host);

    http::write(socket, req);

    beast::flat_buffer buffer;
    http::response<http::dynamic_body> res;
    http::read(socket, buffer, res);

    return res.result() == http::status::ok;
}

int main(int argc, char* argv[]) {
    std::string outfile;
    
    static option opts[] = {
        {"output", required_argument, nullptr, 'o'},
        {0,0,0,0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "o:", opts, nullptr)) != -1) {
        if (c == 'o')
            outfile = optarg;
    }

    if (optind >= argc) {
        std::cerr << "Usage: mycurl [-o file] URL\n";
        return 1;
    }

    std::string url = argv[optind];
    (void)outfile;
    (void)url;

    return 0;
}