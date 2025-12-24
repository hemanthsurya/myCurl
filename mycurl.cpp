#include <getopt.h>
#include <iostream>
#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <filesystem>
#include <chrono>
#include <iomanip>

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

static void print_cert(ssl::stream<tcp::socket>& stream) {
    X509* cert = SSL_get_peer_certificate(stream.native_handle());
    if (!cert) return;

    char subj[512], iss[512];
    X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
    X509_NAME_oneline(X509_get_issuer_name(cert), iss, sizeof(iss));

    std::cout << "Server certificate:\n";
    std::cout << "  Subject: " << subj << "\n";
    std::cout << "  Issuer:  " << iss << "\n";

    X509_free(cert);
}

static bool get_method(const std::string& url, const std::string& outfile, std::string& redirect, std::size_t& body_bytes) 
{
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
    
    if (!outfile.empty()) {
        http::response<http::file_body> res;
        beast::error_code ec;

        res.body().open(outfile.c_str(), beast::file_mode::write, ec);
        if (ec) throw beast::system_error(ec);

        for (auto const& h : res.base())
            std::cout << h.name_string() << ": " << h.value() << "\n";

        if (res.result_int() >= 300 && res.result_int() < 400 &&
            res.base().count(http::field::location))
        {
            redirect = res.base()[http::field::location].to_string();
            res.body().close();
            return true;
        }

        res.body().close();
        body_bytes = std::filesystem::file_size(outfile);
        return false;
    }

    else {
        http::response<http::dynamic_body> res;

        for (auto const& h : res.base())
            std::cout << h.name_string() << ": " << h.value() << "\n";

        if (res.result_int() >= 300 && res.result_int() < 400 &&
            res.base().count(http::field::location))
        {
            redirect = res.base()[http::field::location].to_string();
            return true;
        }

        body_bytes = res.body().size();
        return false;
    }

    if (u.scheme == "https") {
        ssl::context ctx(ssl::context::tls_client);
        ctx.set_default_verify_paths();

        ssl::stream<tcp::socket> stream(ioc, ctx);
        SSL_set_tlsext_host_name(stream.native_handle(), u.host.c_str());
        net::connect(stream.next_layer(), results);
        stream.handshake(ssl::stream_base::client);

        print_cert(stream);
    }
    else {
        tcp::socket socket(ioc);
        net::connect(socket, results);
    }
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

    std::string redirect;
    int redirects = 0;
    std::size_t body_size = 0;

    while (true) {
        bool is_redirect = get_method(url, outfile, redirect, body_size);
        if (!is_redirect) break;

        std::cout << "Redirected to: " << redirect << "\n";
        url = redirect;

        if (++redirects >= 10) {
            std::cerr << "Too many redirects\n";
            return 1;
        }
    }

    return 0;
}