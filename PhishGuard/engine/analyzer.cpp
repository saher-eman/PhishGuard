#include <iostream>
#include <string>
#include <vector>
#include <cctype>
using namespace std;

struct URLParts { string protocol, domain, path; };

struct URLFeatures {
    bool https;
    int length;
    int dots;
    int subdomains;
    bool ipHost;
    bool hasAt;
    bool hyphenInHost;
    bool hasPercent;
};

// ---------- Step 1: URL ko todna ----------
URLParts parseURL(const string& url) {
    URLParts p;
    string rest;
    size_t pos = url.find("://");
    if (pos != string::npos) {
        p.protocol = url.substr(0, pos);
        rest = url.substr(pos + 3);
    } else {
        rest = url;
    }
    size_t slash = rest.find_first_of("/?#");
    if (slash == string::npos) {
        p.domain = rest;
    } else {
        p.domain = rest.substr(0, slash);
        p.path = rest.substr(slash);
    }
    return p;
}

// user@host:port me se sirf host nikalna
string getHost(string domain) {
    size_t at = domain.rfind('@');
    if (at != string::npos) domain = domain.substr(at + 1);
    size_t colon = domain.find(':');
    if (colon != string::npos) domain = domain.substr(0, colon);
    return domain;
}

// ---------- Step 2: Features ----------
string toLower(string s) {
    for (char& c : s) c = tolower((unsigned char)c);
    return s;
}

int countChar(const string& s, char ch) {
    int n = 0;
    for (char c : s) if (c == ch) n++;
    return n;
}

bool isIPHost(const string& host) {
    int parts = 0;
    size_t start = 0;
    while (true) {
        size_t dot = host.find('.', start);
        string seg = host.substr(start, dot == string::npos ? string::npos : dot - start);
        if (seg.empty() || seg.size() > 3) return false;
        for (char c : seg) if (!isdigit((unsigned char)c)) return false;
        if (stoi(seg) > 255) return false;
        parts++;
        if (dot == string::npos) break;
        start = dot + 1;
    }
    return parts == 4;
}

URLFeatures extractFeatures(const string& url) {
    URLParts p = parseURL(url);
    string host = getHost(p.domain);

    URLFeatures f;
    f.https = (toLower(p.protocol) == "https");
    f.length = (int)url.size();
    f.dots = countChar(url, '.');
    int hostDots = countChar(host, '.');
    f.subdomains = hostDots >= 2 ? hostDots - 1 : 0;   // www.google.com => 1
    f.ipHost = isIPHost(host);
    f.hasAt = url.find('@') != string::npos;
    f.hyphenInHost = host.find('-') != string::npos;
    f.hasPercent = url.find('%') != string::npos;
    return f;
}

// ---------- Step 3: Indicators ----------
vector<string> getIndicators(const URLFeatures& f) {
    vector<string> ind;
    if (!f.https)          ind.push_back("No HTTPS");
    if (f.length > 75)     ind.push_back("Unusually long URL");
    if (f.subdomains >= 3) ind.push_back("Too many subdomains");
    if (f.ipHost)          ind.push_back("IP address used as host");
    if (f.hasAt)           ind.push_back("Contains '@' symbol");
    if (f.hyphenInHost)    ind.push_back("Hyphen in domain name");
    if (f.hasPercent)      ind.push_back("Contains percent-encoding");
    return ind;
}

// ---------- Step 4: Risk level ----------
string getRisk(size_t count) {
    if (count == 0) return "LOW";
    if (count <= 2) return "MEDIUM";
    return "HIGH";
}

// ---------- Step 5: JSON output ----------
string jsonEscape(const string& s) {
    string out;
    for (char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if ((unsigned char)c < 0x20) out += ' ';
        else out += c;
    }
    return out;
}

string b(bool v) { return v ? "true" : "false"; }

int main(int argc, char* argv[]) {
    string url;
    if (argc >= 2) {
        url = argv[1];                 // Flask isi tarah call karega
    } else {
        cout << "Enter URL: ";         // manual testing ke liye
        cin >> url;
    }
    if (url.empty()) {
        cerr << "No URL provided\n";
        return 1;
    }

    URLFeatures f = extractFeatures(url);
    vector<string> ind = getIndicators(f);

    cout << "{\n";
    cout << "  \"risk\": \"" << getRisk(ind.size()) << "\",\n";
    cout << "  \"features\": {"
         << "\"https\": " << b(f.https)
         << ", \"length\": " << f.length
         << ", \"dots\": " << f.dots
         << ", \"subdomains\": " << f.subdomains
         << ", \"ip_host\": " << b(f.ipHost)
         << ", \"has_at\": " << b(f.hasAt)
         << ", \"hyphen_in_host\": " << b(f.hyphenInHost)
         << ", \"has_percent\": " << b(f.hasPercent)
         << "},\n";
    cout << "  \"indicators\": [";
    for (size_t i = 0; i < ind.size(); i++) {
        if (i) cout << ", ";
        cout << "\"" << jsonEscape(ind[i]) << "\"";
    }
    cout << "]\n}\n";
    return 0;
}
