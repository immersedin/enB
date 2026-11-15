#pragma once

#include <string>

// Minimal OpenAI-compatible chat-completions client used for the
// AI-assisted danger assessment. Defaults target Pollinations.ai
// (https://text.pollinations.ai) — no API key required; any other
// OpenAI-compatible endpoint works by overriding base_url/model.
namespace ai {

struct AiEndpoint {
    std::string base_url = "https://text.pollinations.ai/openai";
    std::string model = "openai-fast";
    std::string api_key;  // optional: Pollinations classic needs none
};

// Send a chat completion request. `system` is the system message,
// `user` the user message. Returns the assistant's text content, or ""
// on failure; `err` (optional) gets a short reason.
std::string chat(const AiEndpoint& ep, const std::string& system,
                 const std::string& user, std::string* err = nullptr);

// Convenience wrapper with the danger-assessment system prompt.
std::string danger_assessment(const AiEndpoint& ep,
                              const std::string& prompt,
                              std::string* err = nullptr);

}  // namespace ai
