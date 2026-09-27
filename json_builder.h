#ifndef JSON_BUILDER_H
#define JSON_BUILDER_H

#include 
#include 
using namespace std;

// This struct is our "container" that holds every feature we extract from a URL
struct URLFEATURES
{
  bool https;           // is the protocol https?
  int length;            // total length of the url
  int dots;               // how many dots are in the domain
  int subdomain;         // how many subdomains are in the domain
  bool isIPHOST;          // is the domain actually a raw IP address?
  bool hasSpecialchar;    // does the url contain suspicious characters?
};

// Takes the finished features + indicators + risk level, and turns them
// into one clean JSON-formatted string that Flask (Python) can read later.
string buildJSON(URLFEATURES f, vector indicators, string risk)
{
    string json = "{\n";
    json += "  \"risk\": \"" + risk + "\",\n";
    json += "  \"features\": {\n";
    json += "    \"https\": " + string(f.https ? "true" : "false") + ",\n";
    json += "    \"length\": " + to_string(f.length) + ",\n";
    json += "    \"dots\": " + to_string(f.dots) + ",\n";
    json += "    \"subdomains\": " + to_string(f.subdomain) + ",\n";
    json += "    \"isIPHost\": " + string(f.isIPHOST ? "true" : "false") + ",\n";
    json += "    \"hasSpecialChars\": " + string(f.hasSpecialchar ? "true" : "false") + "\n";
    json += "  },\n";
    json += "  \"indicators\": [";
    for (int i = 0; i < indicators.size(); i++) {
        json += "\"" + indicators[i] + "\"";
        if (i != indicators.size() - 1) json += ", "; // no comma after the last item
    }
    json += "]\n";
    json += "}";
    return json;
}

#endif
