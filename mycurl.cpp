#include <getopt.h>
#include <iostream>

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