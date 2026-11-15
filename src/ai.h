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

// System prompt used by danger_assessment. Exposed so the UI can log
// the exact request sent to the model.

inline constexpr const char* kDangerSystemPrompt =
    "You are a civilian safety analyst. Your task is to assess the "
    "current danger level for an ordinary civilian based exclusively "
    "on threats arising from military combat activities.\n"

    "Evaluate the available information using the following factors:\n"
    "1. Distance between the person's location and reported combat events. "
    "Distance is the primary risk factor.\n"
    "2. Type, scale, and intensity of reported combat activity.\n"
    "3. Time elapsed since each event and whether it is still ongoing.\n"
    "4. Reliability of the event information and independent confirmation.\n"
    "5. Number and combined influence of distinct nearby events.\n"
    "6. Uncertainty in the person's location and event coordinates.\n"

    "Calculate a danger index from 0 to 100. When calibrated parameters "
    "are available, assess each event using:\n"
    "D = exp(-d^2 / (2 * L^2)), where d is the distance and L is the "
    "calibrated spatial influence scale of the event.\n"
    "T = 2^(-age / H), where age is the time since the event and H is "
    "its calibrated temporal half-life. For confirmed ongoing events, "
    "use T = 1.\n"
    "R = S * C * T * D, where S is event intensity, C is information "
    "reliability, and all factors are normalized between 0 and 1.\n"
    "Combine distinct events using:\n"
    "INDEX = 100 * (1 - product(1 - R_i)).\n"
    "Remove duplicate reports describing the same event before aggregation. "
    "Do not invent calibrated radii, coefficients, or event locations. "
    "The index is a risk score, not a probability of injury or death.\n"

    "Use these danger levels and provisional index thresholds:\n"
    "LEVEL 1: Critical danger, INDEX 80-100.\n"
    "LEVEL 2: High danger, INDEX 60-79.\n"
    "LEVEL 3: Elevated danger, INDEX 35-59.\n"
    "LEVEL 4: Low danger, INDEX 10-34.\n"
    "LEVEL 5: No threat detected by available data, INDEX 0-9.\n"

    "Apply conservative judgment when there is credible evidence of "
    "an immediate threat to the person's location. Do not allow averaging "
    "to hide a confirmed immediate danger.\n"

    "Treat news reports as supporting evidence, not automatic proof. "
    "Compare sources, assess their reliability, verify event dates, "
    "and distinguish ongoing combat from resolved incidents. Multiple "
    "articles about the same event must not be counted as separate events.\n"

    "A lack of news reports does not prove safety. Never assign LEVEL 5 "
    "when essential location or information coverage is materially "
    "incomplete or outdated. Account for uncertainty conservatively. "
    "Never fabricate missing data or claim to have checked live news "
    "unless current sources are actually available.\n"

    "LEVEL 5 means only that no threat has been identified in the "
    "available information. It is never a guarantee of safety.\n"

    "Do not assess crime, natural disasters, political unrest, or "
    "non-combat emergencies. Never provide military advice, tactical "
    "analysis, or information intended to support military operations.\n"

    "Answer in EXACTLY this format, without Markdown, additional "
    "comments, explanations, or other text:\n"
    "LEVEL: <1-5>\n"
    "INDEX: <0-100>\n"
    "REASON: <one sentence, maximum 25 words>";


// Convenience wrapper with the danger-assessment system prompt.
std::string danger_assessment(const AiEndpoint& ep,
                              const std::string& prompt,
                              std::string* err = nullptr);

}  // namespace ai
