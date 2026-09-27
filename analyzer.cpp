#include 
#include 
#include 
#include "json_builder.h"   // brings in URLFEATURES struct + buildJSON()
using namespace std;

// ---------- FEATURE FUNCTIONS ----------

// Feature 1: is the protocol https?
bool hasHTTPS(string protocol) {
    return protocol == "https";
}

// Feature 2: how long is the whole url?
int urllengtH(string url) {
    return url.length();
}

// Feature 3: how many dots are in the domain?
int countdots(string domain) {
    int coount = 0;
    for (int i = 0; i < domain.size(); i++) {
        if (domain[i] == '.') coount++;
    }
    return coount;
}

// Feature 4: rough subdomain count
int countsubdomains(int dots) {
    int subs = dots - 1;
    if (subs < 0) subs = 0;
    return subs;
}

// Feature 5: is the domain a raw IP address?
bool isIPHOST(string domain) {
    for (int i = 0; i < domain.size(); i++) {
        if ((domain[i] >= '0' && domain[i] <= '9') || domain[i] == '.')
            continue;
        else
            return false;
    }
    return true;
}

// Feature 6: does the url contain suspicious special characters?
bool hasSpecialChar(string url) {
    for (int i = 0; i < url.size(); i++) {
        if ((url[i] >= 'a' && url[i] <= 'z') ||
            (url[i] >= 'A' && url[i] <= 'Z') ||
            (url[i] >= '0' && url[i] <= '9') ||
            url[i] == '.' || url[i] == '-' ||
            url[i] == ':' || url[i] == '/' ||
            url[i] == '?' || url[i] == '=' ||
            url[i] == '&')
            continue;
        else
            return true;
    }
    return false;
}

// ---------- INDICATORS + RISK ----------

// Turns raw features into human-readable warning messages
vector getIndicators(URLFEATURES F) {
    vector indicators;

    if (!F.https) indicators.push_back("No HTTPS");
    if (F.isIPHOST) indicators.push_back("IP address used as host");
    if (F.length > 75) indicators.push_back("Unusually long URL");
    if (F.subdomain > 2) indicators.push_back("Too many subdomains");
    if (F.hasSpecialchar) indicators.push_back("Suspicious special characters");

    return indicators;
}

// Decides overall risk level based on how many indicators fired
string getRiskLevel(vector indicators) {
    int count = indicators.size();
    if (count == 0) return "LOW CONCERN";
    else if (count <= 2) return "MEDIUM CONCERN";
    else return "HIGHER CONCERN";
}

// ---------- MAIN PROGRAM ----------

int main()
{
    string url;
    cout << "Enter the URL :";
    cin >> url;

    // Step 1: separate protocol from the rest
    size_t protocolEnd = url.find("://");
    string protocol = "";
    string rest = url;

    if (protocolEnd != string::npos) {
        protocol = url.substr(0, protocolEnd);
        rest = url.substr(protocolEnd + 3);
    }

    // Step 2: separate domain from path
    size_t pathstart = rest.find("/");
    string domain = rest;
    string path = "";

    if (pathstart != string::npos) {
        domain = rest.substr(0, pathstart);
        path = rest.substr(pathstart);
    }

    cout << "You Entered : " << url << endl;
    cout << "Protocol : " << protocol << endl;
    cout << "Domain : " << domain << endl;
    cout << "Path : " << path << endl;

    // Step 3: fill the struct using our feature functions
    URLFEATURES F;
    F.https = hasHTTPS(protocol);
    F.length = urllengtH(url);
    F.dots = countdots(domain);
    F.subdomain = countsubdomains(F.dots);
    F.isIPHOST = isIPHOST(domain);
    F.hasSpecialchar = hasSpecialChar(url);

    cout << "HTTPS :" << (F.https ? "Yes" : "No") << endl;
    cout << "URL Length : " << F.length << endl;
    cout << "Dots in Domain : " << F.dots << endl;
    cout << "Subdomains in Domain : " << F.subdomain << endl;
    cout << "Is IP Host : " << (F.isIPHOST ? "Yes" : "No") << endl;
    cout << "Has Special Character : " << (F.hasSpecialchar ? "Yes" : "No") << endl;

    // Step 4: build indicators + risk level from the completed features
    vector indicators = getIndicators(F);
    string risk = getRiskLevel(indicators);

    // Step 5: build and print final JSON output
    string json = buildJSON(F, indicators, risk);
    cout << "\n--- JSON Output ---\n" << json << endl;

    return 0;
}
