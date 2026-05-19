# NEXUS-SOC: AI-Powered Security Operations Center
## Multi-Agent System — Technical Report
**Submitted by:** Ritwik Reddy Kolan  
**Live System:** http://nexus-production.eba-xcncmpcj.us-east-1.elasticbeanstalk.com  
**GitHub:** https://github.com/Ritwik2412/nexus-soc  

---

## 1. Multi-Agent Architecture

NEXUS-SOC is a six-agent AI pipeline designed to automate the first-response 
triage of cybersecurity incidents. The system addresses a real enterprise pain 
point: SOC teams are overwhelmed by alert volume and require fast, structured, 
defensible incident responses.

**Agent Roster and Responsibilities:**

- **Guard Agent** — The security gate. Every input is classified for prompt 
injection attempts, jailbreaks, malformed data, and PII risks before entering 
the pipeline. Invalid inputs are rejected with a structured reason code.

- **Ingestion Agent** — Parses raw alert text into structured JSON, extracting 
source IPs, target systems, alert types, severity estimates, and indicators 
of compromise. Produces a normalized alert object passed downstream.

- **Threat Intelligence Agent** — Performs deep threat analysis on the parsed 
alert. Classifies the threat actor type (APT, cybercriminal, insider, etc.), 
scores the threat from 0–100, identifies known attack patterns, and determines 
whether escalation is required.

- **Remediation Agent** — Generates a concrete, prioritized action plan with 
immediate, short-term, and long-term actions. Specifies containment strategy, 
estimated resolution time, and whether human approval is required.

- **Review Agent** — The quality gate. Critically evaluates the remediation 
plan for completeness, safety, and coverage. If the plan is inadequate, the 
Review Agent rejects it with specific revision instructions, triggering a 
retry loop back to the Remediation Agent. This repeats up to 2 times.

- **Reporter Agent** — Compiles all agent outputs into a structured incident 
brief with seven sections: Incident Summary, Threat Classification, Indicators 
of Compromise, Remediation Plan, Review Findings, Risk Assessment, and 
Recommended Next Steps.

**Communication Pattern:**  
Agents operate in a sequential + cyclical hybrid pipeline. The 
Remediation ↔ Review loop implements genuine agent negotiation — structured 
JSON revision instructions flow from the Review Agent back to the Remediation 
Agent, which must revise and resubmit. All inter-agent messages are structured 
JSON objects passed through the FastAPI orchestration layer. No agent can 
invoke another directly — all routing is controlled by the backend.

---

## 2. Security, Safety, and Guardrails

Security is a first-class concern at every layer of NEXUS-SOC:

- **Prompt Injection Defense:** The Guard Agent runs before any LLM sees the 
input. It classifies inputs using a strict system prompt that explicitly 
enumerates injection patterns, jailbreak attempts, and malformed data.

- **Role Constraint Enforcement:** Each agent operates under a scoped system 
prompt that defines its exact responsibilities and output format. No agent 
has visibility into other agents' system prompts or the ability to invoke 
other agents.

- **Output Filtering:** The Review Agent acts as a structural output filter, 
rejecting remediation plans that are incomplete, unsafe, or missing critical 
steps before they reach the Reporter.

- **Retry Limit Enforcement:** The retry loop is capped at 2 iterations to 
prevent infinite loops and uncontrolled LLM spend. After 2 retries, the 
Reporter proceeds with the best available plan.

- **Secret Management:** API keys are injected via AWS Elastic Beanstalk 
environment variables and never stored in version-controlled files.

- **Full Audit Trail:** Every agent invocation — including all retry attempts 
— is logged with raw input and output, visible in the Agent Trace tab.

---

## 3. Implementation Approach

**Stack:**
- **Backend:** Python 3.12, FastAPI, Uvicorn, Gunicorn
- **LLM Provider:** Groq API (Llama 3.3 70B Versatile)
- **Orchestration:** Custom sequential pipeline with cyclical retry loop
- **Frontend:** Vanilla HTML/CSS/JS with dark SOC-themed UI
- **Cloud:** AWS Elastic Beanstalk (us-east-1), single EC2 instance
- **Version Control:** Git, GitHub (public repository)

**Agent Instantiation:**  
Agents are stateless functions in `agents.py`. Each call to `call_agent()` 
constructs a fresh prompt from the agent's system prompt and the current 
pipeline context. The orchestrator in `run_pipeline()` manages state, passing 
structured outputs between agents.

**Error Handling:**  
JSON parse failures are caught and surfaced as pipeline errors without 
crashing the system. The retry loop handles Review Agent rejections gracefully. 
All exceptions are caught at the FastAPI layer and returned as structured 
HTTP error responses.

**Testing Approach:**  
Four representative attack scenarios were used for end-to-end validation: 
SSH brute force, data exfiltration, malware detection, and DDoS attack. 
The Guard Agent was tested with prompt injection attempts to verify blocking.

---

## 4. Use of AI / LLMs and Collaboration

**LLM Usage by Agent:**
- Guard Agent: Classification and structured safety assessment
- Ingestion Agent: Information extraction and normalization
- Threat Intel Agent: Reasoning and threat scoring
- Remediation Agent: Planning and action generation
- Review Agent: Critique, gap analysis, and negotiation
- Reporter Agent: Summarization and structured report generation

**Agent Collaboration:**  
The most sophisticated collaboration is the Remediation ↔ Review negotiation 
loop. The Review Agent does not simply approve or reject — it produces 
structured revision_instructions that the Remediation Agent must incorporate. 
This is a genuine multi-agent negotiation pattern, not a simple pipeline.

**Autonomy vs. Control Trade-offs:**  
The system deliberately maintains human oversight at two levels. First, 
high-severity plans set requires_human_approval: true, flagging that a human 
must authorize execution. Second, the retry loop is bounded — the system will 
not loop indefinitely. These design choices prioritize safe, auditable 
AI-assisted decision-making over full autonomy, which is appropriate for a 
security operations context where incorrect actions could cause harm.