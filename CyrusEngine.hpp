/*
 * =====================================================================================
 * PROJECT CYRUS — Next-Gen C++ LLM Security Firewall & Guardrail Engine
 * File: CyrusEngine.hpp
 * Description: Header file defining the C++ Security Engine, RAG document scanner,
 *              Honeypot decoy generator, Policy configuration rules, OpenAI Proxy payload
 *              models, and extensive inline interview Q&A comments.
 * 
 * 🎓 INTERVIEW PREP & DEEP DIVE SECTION INCLUDED IN COMMENTS BELOW
 * =====================================================================================
 */

#ifndef CYRUS_ENGINE_HPP
#define CYRUS_ENGINE_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <regex>
#include <chrono>

namespace cyrus {

/// Severity level of detected threat in CYRUS
enum class SeverityLevel {
    SECURE = 0,   // No threats or sensitive data found
    LOW = 1,      // Minor heuristic match or public metadata
    MEDIUM = 2,   // Suspicious system phrasing or low-confidence PII
    HIGH = 3,     // Definite Prompt Injection or PII leak (API Keys, Credit Cards)
    CRITICAL = 4  // Jailbreak exploit + API Key leak combined / System prompt override
};

/// Types of security violations CYRUS can detect
enum class ViolationType {
    NONE,
    JAILBREAK_DAN,            // "Do Anything Now" / Unrestricted mode exploits
    SYSTEM_PROMPT_EXTRACTION,  // Attempting to reveal system instructions
    DELIMITER_HIJACKING,      // Escaping markdown/JSON tags to trick model
    ROLEPLAY_EXPLOIT,         // Evil persona / simulated restriction removal
    INDIRECT_INJECTION_RAG,   // Hidden prompt injection inside RAG documents/PDFs
    PII_API_KEY,              // OpenAI, AWS, GitHub, JWT API Keys
    PII_CREDIT_CARD,          // Credit Card numbers (Luhn check pattern)
    PII_SSN,                  // Social Security Numbers
    PII_PASSWORD,             // Hardcoded passwords / connection strings
    CUSTOM_BLACK_LIST         // User-configured custom forbidden terms
};

/// Detailed report of an individual security violation flag
struct SecurityViolation {
    ViolationType type;
    SeverityLevel severity;
    std::string ruleName;         // E.g., "DAN_JAILBREAK_V3"
    std::string description;      // Human-readable explanation for security logs
    std::string matchedSubstring; // Exact string segment that triggered the flag
    size_t startIndex;            // Position offset in prompt
    size_t length;                // Segment length
};

/// Complete security assessment returned by CYRUS for a given prompt
struct AnalysisResult {
    bool isFlagged;                     // True if risk score >= threshold
    double riskScore;                   // Normalized risk score from 0.0 to 100.0
    SeverityLevel overallSeverity;      // Highest severity detected
    std::string sanitizedPrompt;        // Prompt with sensitive PII redacted
    std::vector<SecurityViolation> violations; // List of all detected threat flags
    long long executionTimeMicros;      // Microsecond latency benchmark
    std::string recommendedAction;     // "BLOCK", "SANITIZE_AND_PASS", "HONEYPOT_DECOY"
    std::string honeypotResponse;       // Active Defense decoy response if enabled
};

/// Configurable security policy settings (Managed via UI Policy Builder)
struct SecurityPolicy {
    bool enableJailbreakDetection = true;
    bool enableSystemPromptProtection = true;
    bool enablePiiScanner = true;
    bool enableObfuscationScanner = true;
    bool enableRagDocumentScanner = true;
    bool enableHoneypotDecoyMode = true; // Feature 2: Active Defense Honeypot
    double riskThreshold = 40.0;          // Score above which prompt is flagged RED (0.0 to 100.0)
    std::vector<std::string> customBlacklist;
    std::string honeypotDecoyPayload = "CYRUS_ACTIVE_DEFENSE: System access restricted. Intrusion payload logged to SOC.";
};

/// OpenAI Proxy Message Format (Feature 6: `/v1/chat/completions`)
struct ChatMessage {
    std::string role;    // "system", "user", or "assistant"
    std::string content; // Message content text
};

struct ChatCompletionPayload {
    std::string model;
    std::vector<ChatMessage> messages;
    double temperature = 0.7;
};

/* 
 * ============================================================================
 * 🎓 INTERVIEW PREP: MODERN C++ CLASS DESIGN & ACTIVE DEFENSE ARCHITECTURE
 * ============================================================================
 * ❓ QUESTION AN INTERVIEWER MIGHT ASK:
 *    "How does CyrusEngine implement Active Defense (Honeypots) and RAG scanning in C++?"
 * 
 * 💡 ANSWER & TECHNICAL REASONING:
 *    1. Active Defense (Honeypot Decoy): Instead of returning an explicit error message (which alerts
 *       the attacker that their injection vector was caught), CYRUS generates a convincing decoy
 *       response that traps the payload while logging attacker telemetry to SOC logs.
 *    2. RAG Document Ingestion Scanning: RAG pipelines retrieve untrusted third-party documents.
 *       `scanRagDocument()` runs multi-pass regex filters across chunked text blocks before
 *       vector embeddings are created, mitigating Indirect Prompt Injection at the boundary!
 * ============================================================================
 */

class CyrusEngine {
public:
    /// Default Constructor initializes standard OWASP LLM Top 10 patterns
    CyrusEngine();

    /// Constructor accepting custom security policy
    explicit CyrusEngine(const SecurityPolicy& policy);

    /// Destructor (Default RAII cleanup)
    ~CyrusEngine() = default;

    /// Primary prompt analysis method — evaluates prompt and returns full security audit
    AnalysisResult analyze(const std::string& rawPrompt) const;

    /// Feature 1: RAG Document & VectorDB Scanner (Indirect Injection)
    AnalysisResult scanRagDocument(const std::string& documentContent, const std::string& documentName = "untrusted_rag_doc.txt") const;

    /// Feature 6: OpenAI Proxy Chat Completions Inspector
    AnalysisResult analyzeChatPayload(const ChatCompletionPayload& payload) const;

    /// Update active engine policy dynamically (Feature 3: Custom Policy Builder)
    void setPolicy(const SecurityPolicy& newPolicy);

    /// Get current engine policy
    SecurityPolicy getPolicy() const;

private:

    // Helper scanning methods
    void scanJailbreakPatterns(const std::string& prompt, std::vector<SecurityViolation>& violations, double& riskAccumulator) const;
    void scanSystemPromptLeaks(const std::string& prompt, std::vector<SecurityViolation>& violations, double& riskAccumulator) const;
    void scanPiiAndCredentials(const std::string& prompt, std::vector<SecurityViolation>& violations, double& riskAccumulator, std::string& outSanitized) const;
    void scanObfuscationTechniques(const std::string& prompt, std::vector<SecurityViolation>& violations, double& riskAccumulator) const;
    void scanCustomBlacklist(const std::string& prompt, std::vector<SecurityViolation>& violations, double& riskAccumulator) const;
    void scanRagIndirectPatterns(const std::string& documentContent, std::vector<SecurityViolation>& violations, double& riskAccumulator) const;

    // Severity helper
    SeverityLevel calculateOverallSeverity(const std::vector<SecurityViolation>& violations) const;
    std::string determineAction(double riskScore, SeverityLevel severity) const;

    SecurityPolicy m_policy;

    // Compiled Regular Expressions for High Performance Scanning
    std::regex m_regexApiKey;
    std::regex m_regexAwsKey;
    std::regex m_regexCreditCard;
    std::regex m_regexSsn;
    std::regex m_regexJwt;
    std::regex m_regexDanJailbreak;
    std::regex m_regexSystemPromptOverride;
    std::regex m_regexBase64Payload;
    std::regex m_regexRagIndirectInjection;
};

} // namespace cyrus

#endif // CYRUS_ENGINE_HPP
