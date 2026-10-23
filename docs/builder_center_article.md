# CyberShield AI: letting a 2B decision model make the call, and an LLM explain it

#strands-decider-2b #policy

**The problem.** SOC analysts drown in alerts. Triage is a routine, repeated decision, which is exactly the kind of
decision an LLM is slow and expensive for.

**The Decider 2B decision.** I ask Strands Decider 2B one typed `choice` question (LOW / MEDIUM / HIGH, with a one-line
policy criterion per option). It returns probabilities and a confidence, not text. Code branches on that number.

**The Bedrock part.** After the decision, a Strands Agent on Amazon Bedrock writes a short explanation and safe next
steps. A `before_tool_call` intervention allows its escalation-draft tool only when the policy decision is HIGH.

**Honesty.** The explanation is the LLM's, not the Decider's. Nothing is blocked or deleted automatically.

**What I learned.** **What I learned.**
1. All 12 automated tests passed in my local environment.
2. A clearly labelled mock mode can demonstrate the interface without claiming that a real decision model is running.
3. Integration checks are important: the local Decider server was unreachable during my test, and Bedrock explanation generation remains unverified.
**Limitations.** Hand-picked policy wording; tiny sample alert set; no real-world validation; requires AWS access for
the generative part; local server has no auth.

Repo: [Add the public GitHub repository URL after publishing]