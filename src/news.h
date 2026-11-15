#pragma once

#include <string>
#include <vector>

// Google News RSS headlines used as unverified context for the AI
// danger assessment. No API key required.
namespace news {

struct Item {
    std::string title;
    std::string published;  // RFC-822 pubDate, may be empty
    std::string source;     // outlet name, may be empty
};

// Fetch Google News RSS search results for `query` (free text, e.g.
// "\"Odessa\" Ukraine shelling"). Returns up to `max_items` headlines,
// newest first; empty vector on failure (`err` gets a short reason
// when provided).
std::vector<Item> google_news(const std::string& query, int max_items,
                              std::string* err = nullptr);

}  // namespace news
