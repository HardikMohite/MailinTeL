# MailIntel — Agentic AI Development Rules

> **Purpose:** This document defines the mandatory operating rules for any AI agent, coding agent, autonomous agent, or developer assistant working on the MailIntel project.
>
> These rules exist to prevent uncontrolled development, architectural drift, duplicate work, broken functionality, false completion claims, and loss of project context.

---

# 1. CORE OPERATING PRINCIPLE

The AI agent must treat the existing MailIntel project as a **living system**, not as a blank project.

Before making changes, the agent must understand:

```text
What has already been built?
        ↓
What currently works?
        ↓
What is the active task?
        ↓
What project decisions already exist?
        ↓
What must not be broken?
```

The agent must prefer:

```text
Understand
    ↓
Inspect
    ↓
Plan
    ↓
Implement
    ↓
Test
    ↓
Update Project State
```

The agent must not:

```text
Assume
    ↓
Rewrite blindly
    ↓
Break existing code
    ↓
Declare success without testing
```

---

# 2. REQUIRED FILES TO READ

Before starting meaningful development work, the agent must read the relevant project documentation.

The primary project state file is:

```text
Tracker.md
```

The agent should also review relevant files such as:

```text
PRD.md
TechSpec.md
AppFlow.md
Design.md
Schema.md
ImplementationPlan.md
Rules.md
```

## Document Authority

Use the following hierarchy when documents conflict:

```text
1. Explicit user instruction
2. Latest confirmed project decision
3. Tracker.md current project state
4. PRD.md product requirements
5. TechSpec.md technical decisions
6. Schema.md data architecture
7. ImplementationPlan.md development sequence
8. AppFlow.md application behavior
9. Design.md UI and visual rules
10. Rules.md agent operating rules
```

If a conflict cannot be safely resolved, the agent must stop and report it rather than silently choosing an incompatible implementation.

---

# 3. TRACKER.md IS THE PROJECT MEMORY

`Tracker.md` represents the actual current state of the project.

Before beginning work, the agent must check:

- Current project phase
- Current task
- Active tasks
- Completed work
- Current blockers
- Known issues
- Important project decisions
- Next action

The agent must not assume that planned features are already implemented.

A feature listed in:

```text
Upcoming Tasks
```

is not necessarily available in the codebase.

A feature listed in:

```text
Completed Work
```

should be preserved unless the user explicitly requests changes.

---

# 4. PRE-DEVELOPMENT RULES

Before modifying code, the agent must:

## Step 1 — Read Project State

Read `Tracker.md`.

## Step 2 — Inspect Existing Code

Inspect relevant:

- Project structure
- Existing modules
- APIs
- Database models
- Configuration
- Dependencies
- Tests
- Existing implementation

## Step 3 — Identify the Exact Task

The agent must identify:

```text
Current Task
Objective
Requirements
Completion Criteria
Dependencies
```

## Step 4 — Check for Existing Implementation

Before creating a new feature, verify whether it already exists partially or completely.

The agent must not duplicate functionality unnecessarily.

## Step 5 — Determine Impact

Before changing existing code, identify:

- Files affected
- APIs affected
- Database impact
- Storage impact
- Frontend impact
- Backward compatibility risks

---

# 5. ONE TASK AT A TIME

The agent should primarily focus on the current task.

Preferred workflow:

```text
TASK-001
   ↓
Implement
   ↓
Test
   ↓
Update Tracker
   ↓
TASK-002
```

Avoid:

```text
TASK-001
TASK-002
TASK-003
TASK-004
       ↓
Partially modify everything
       ↓
Leave unfinished dependencies
```

The agent may perform small supporting changes required for the active task.

However, it must not start unrelated features without justification.

---

# 6. DO NOT OVERENGINEER

Build according to the current project phase.

The agent must not prematurely implement:

- Authentication
- RBAC enforcement
- OAuth integrations
- Browser extension functionality
- Production-scale distributed infrastructure
- Unrequested microservices

when those features are explicitly deferred.

Current MailIntel strategy:

```text
Core forensic intelligence MVP
        ↓
Stable end-to-end workflow
        ↓
Authentication
        ↓
RBAC enforcement
        ↓
OAuth integrations
        ↓
Browser extension
```

The architecture should remain ready for future development without building every future feature immediately.

---

# 7. PRESERVE THE APPROVED ARCHITECTURE

The agent must respect established technical decisions.

## PostgreSQL

Used for structured data such as:

- Analysis records
- Email metadata
- Findings
- Relationships
- Indicators
- Intelligence references
- Integrity metadata
- Relevant vector records

## pgvector

Used for approved vector and semantic similarity capabilities.

## MinIO

Used for:

- Original `.eml` evidence
- Large binary evidence objects
- Other approved artifacts

The original evidence must remain preserved.

## Redis

Used for:

- Caching
- Temporary processing support
- Background processing support where required

Redis must not become permanent forensic evidence storage.

---

# 8. FORENSIC EVIDENCE RULES

MailIntel is an email forensic intelligence platform.

The agent must treat original evidence carefully.

For original `.eml` files:

```text
Receive
    ↓
Validate
    ↓
Calculate SHA-256
    ↓
Preserve Original
    ↓
Store Metadata
    ↓
Analyze Derived Data
```

The agent must not intentionally modify original evidence.

If derived or normalized data is created, it must remain distinguishable from the original evidence.

The system should preserve the relationship between:

```text
Evidence Record
      +
SHA-256
      +
Object Storage Reference
      +
Analysis Record
```

---

# 9. NO FALSE FORENSIC CLAIMS

The agent must avoid implementing UI or language that overstates what the evidence proves.

Examples:

Do not automatically claim:

```text
"The attacker is located in India."
```

when the evidence only supports:

```text
"Observed infrastructure IP is geolocated in India."
```

Do not automatically claim:

```text
"This email belongs to Campaign X."
```

when only weak similarity exists.

Prefer evidence-based language such as:

```text
Potential correlation
Shared infrastructure
Observed similarity
Related indicator
Campaign hypothesis
```

The UI and backend logic must preserve uncertainty where appropriate.

---

# 10. SCORING RULES

Do not collapse all intelligence into one unexplained score.

MailIntel distinguishes between concepts such as:

## Threat Risk Score

How suspicious or risky the analyzed email appears based on defined signals.

## Evidence Confidence Score

How strongly the available evidence supports a finding or conclusion.

## Campaign Confidence

How strongly available signals support a correlation or campaign hypothesis.

The agent must not automatically treat these as the same thing.

Every important score should be traceable to understandable contributing signals.

---

# 11. SIMILARITY AND CAMPAIGN RULES

Semantic similarity is a correlation signal.

Email DNA similarity is a correlation signal.

Shared indicators are correlation signals.

None of these alone should automatically prove campaign membership unless the implemented project logic explicitly supports such a conclusion with sufficient evidence.

The agent should support relationships such as:

```text
Email A
   │
   ├── Shared URL ───── Email B
   │
   └── Similar Content ─ Email C
```

An entity may participate in multiple investigative relationships.

Do not force a simplistic one-email-to-one-campaign model if evidence supports overlapping relationships.

---

# 12. GEOLOCATION RULES

Geolocation must be represented accurately.

The location of:

- An IP address
- A hosting provider
- A VPN endpoint
- A cloud server

does not automatically identify the physical location of an attacker.

The agent must ensure:

- Data source is retained where possible
- Infrastructure location is clearly distinguished from actor attribution
- Uncertainty is not hidden

---

# 13. API AND EXTERNAL SERVICE RULES

When integrating external APIs or intelligence providers:

1. Use environment variables for credentials.
2. Never hardcode secrets or API keys.
3. Handle unavailable providers gracefully.
4. Record source/provider information where relevant.
5. Avoid making one external API a single point of failure.
6. Respect rate limits where applicable.
7. Cache suitable non-sensitive data when architecturally appropriate.
8. Do not present third-party intelligence as unquestionable fact.

Provider integrations should preferably be modular enough to allow replacement or fallback.

---

# 14. SECURITY RULES

The agent must:

- Never expose secrets in frontend code
- Never commit credentials
- Use environment variables for sensitive configuration
- Validate user-controlled input
- Avoid unsafe file handling
- Apply appropriate file size restrictions
- Avoid exposing internal error details unnecessarily
- Protect object storage access appropriately
- Validate API input before processing

The agent must not silently disable security controls merely to make development easier without recording the reason.

---

# 15. DATABASE CHANGE RULES

Before changing the database schema, the agent must:

1. Inspect the existing schema.
2. Review `Schema.md`.
3. Determine migration impact.
4. Avoid destructive changes unless explicitly approved.
5. Preserve existing data where practical.
6. Update relevant documentation and tracker records.

Do not:

```text
Drop database
Recreate everything
Lose evidence records
```

as a shortcut unless explicitly authorized.

---

# 16. FILE AND OBJECT STORAGE RULES

Before changing object storage behavior, the agent must consider:

- Existing object paths
- Evidence references
- Integrity relationships
- Backward compatibility
- Cleanup impact

The agent must not delete original evidence automatically unless an approved retention policy explicitly permits it.

---

# 17. UI IMPLEMENTATION RULES

The UI must follow the approved design direction in `Design.md`.

The agent should:

- Preserve the single-theme design strategy
- Use the approved typography approach
- Maintain professional forensic/intelligence aesthetics
- Avoid unnecessary visual clutter
- Clearly distinguish available, processing and future features

Feature state must be represented honestly.

Examples:

```text
AVAILABLE
PROCESSING
PLANNED
COMING SOON
```

Do not create fake working interfaces for unimplemented functionality.

---

# 18. DESIGN BEFORE COMPLEX IMPLEMENTATION

For complex changes, the agent should first determine:

```text
Input
    ↓
Processing
    ↓
Storage
    ↓
Output
```

For example:

```text
.eml File
    ↓
Upload Validation
    ↓
SHA-256
    ↓
MinIO Storage
    ↓
PostgreSQL Metadata
    ↓
Background Analysis
    ↓
Findings
    ↓
Investigation UI
```

Do not write large amounts of disconnected code before understanding the complete data flow.

---

# 19. TESTING IS MANDATORY

Code written does not mean a feature is complete.

A task should generally follow:

```text
PENDING
    ↓
IN_PROGRESS
    ↓
TESTING
    ↓
COMPLETED
```

The agent must test relevant functionality before marking it complete.

Testing should include, where applicable:

- Happy path
- Invalid input
- Failure behavior
- Integration with existing systems
- Data persistence
- Regression risks

The exact test method depends on the feature.

---

# 20. DO NOT FAKE TEST RESULTS

The agent must never claim:

```text
"Tests passed"
```

without actually running or performing the relevant validation.

If tests cannot be run, the agent must state that clearly.

For example:

```text
Implementation completed.
Automated testing could not be run because the required service is unavailable.
Status remains: TESTING
```

This is preferable to falsely marking a task as complete.

---

# 21. ERROR HANDLING RULES

The agent must not hide errors.

When an operation fails:

```text
Detect Failure
    ↓
Record Relevant Details
    ↓
Return Safe Error Response
    ↓
Preserve Application Stability
```

Avoid:

- Silent failures
- Empty success responses after failed operations
- Catch-all exceptions that hide root causes
- Deleting data to bypass an error

---

# 22. BLOCKER RULE

When a genuine blocker occurs, the agent must update `Tracker.md`.

A blocker should include:

```text
What is blocked?
Why is it blocked?
What was attempted?
What evidence or error was observed?
Possible next step
```

Do not repeatedly attempt the same failed approach without reassessing the cause.

---

# 23. DOCUMENTATION UPDATE RULE

The agent must update documentation when a meaningful implementation changes the actual project state.

Examples:

| Change | Documentation to Consider |
|---|---|
| Task completed | Tracker.md |
| Architecture changed | TechSpec.md |
| Database changed | Schema.md |
| Product requirement changed | PRD.md |
| Page or workflow changed | AppFlow.md |
| Visual system changed | Design.md |
| Development sequence changed | ImplementationPlan.md |
| Agent behavior rule changed | Rules.md |

Do not update documents merely to make them look current.

Update them when reality changes.

---

# 24. TRACKER UPDATE RULE

After meaningful development work, the agent must update `Tracker.md`.

Update:

## Current Task

Change its status appropriately.

## Completed Work

Move genuinely completed and tested tasks here.

## Testing Record

Record meaningful test results.

## Current Blockers

Add unresolved blockers.

## Known Issues

Record limitations that remain.

## Next Action

Set the most logical next action.

The tracker must reflect:

```text
Actual State
```

not:

```text
What the agent hopes is true
```

---

# 25. GIT AND CHANGE MANAGEMENT

When Git is available, the agent should:

1. Inspect the working tree before major changes.
2. Avoid overwriting unrelated changes.
3. Keep changes logically scoped.
4. Review modified files before finalizing.
5. Avoid committing secrets.
6. Avoid destructive resets unless explicitly authorized.

The agent must not discard user-created work simply because it is unfamiliar.

---

# 26. DEPENDENCY RULES

Before adding a dependency:

- Check whether the project already has an equivalent dependency.
- Prefer existing approved tooling where reasonable.
- Avoid adding packages for trivial functionality.
- Check compatibility with the existing stack.

Do not add multiple libraries that solve the same problem without a clear reason.

---

# 27. NO UNAUTHORIZED MAJOR REWRITES

The agent must not perform a large architectural rewrite simply because it prefers another technology or structure.

Major changes require justification when they affect:

- Backend architecture
- Frontend framework
- Database
- Object storage
- Core analysis pipeline
- Existing data model

Prefer incremental improvement unless a rewrite is explicitly requested or clearly necessary.

---

# 28. COMPLETION DEFINITION

A task is considered complete only when:

```text
Requirements Implemented
        +
Relevant Testing Performed
        +
No Critical Known Failure
        +
Tracker Updated
```

If one of these is missing, the task should normally remain:

```text
IN_PROGRESS
```

or:

```text
TESTING
```

---

# 29. WHEN TO ASK FOR CLARIFICATION

The agent should ask for clarification rather than guess when:

- Two project documents conflict materially
- A requested feature changes a confirmed architecture decision
- Required credentials or external access are missing
- A destructive operation may cause data loss
- The user's intended behavior is genuinely ambiguous

The agent should not ask unnecessary questions when the answer already exists in the project documentation or codebase.

---

# 30. FINAL AGENT CHECKLIST

Before declaring a development session complete, verify:

```text
[ ] I read Tracker.md before starting
[ ] I understood the current task
[ ] I inspected relevant existing code
[ ] I avoided unrelated work
[ ] I followed approved architecture
[ ] I preserved evidence integrity rules
[ ] I did not expose secrets
[ ] I tested meaningful changes
[ ] I did not falsely claim tests passed
[ ] I recorded blockers or limitations
[ ] I updated Tracker.md
[ ] I set the correct next action
```

---

# FINAL PRINCIPLE

> **The AI agent is a contributor to the MailIntel project, not the uncontrolled owner of it.**

The agent must:

```text
Understand before changing
Preserve before replacing
Implement before claiming
Test before completing
Document before moving on
```

Every development action should leave the project in a state that the next AI agent or developer can understand and continue safely.


---

# 31. MANDATORY FEATURE VALIDATION BEFORE MOVING FORWARD

> **Critical Rule:** The AI agent must not move to the next major feature or task simply because the current feature appears implemented.

Every completed feature must pass a structured validation process before the agent advances.

The required sequence is:

```text
IMPLEMENT
    ↓
FUNCTIONAL VERIFICATION
    ↓
COMPONENT VERIFICATION
    ↓
API VERIFICATION
    ↓
INTEGRATION VERIFICATION
    ↓
SECURITY REVIEW
    ↓
RELEVANT VAPT / SECURITY TESTING
    ↓
FIX CRITICAL ISSUES
    ↓
REGRESSION TEST
    ↓
UPDATE TRACKER
    ↓
MOVE TO NEXT TASK
```

A feature that fails any critical stage must remain in:

```text
IN_PROGRESS
```

or:

```text
TESTING
```

The agent must not mark it as `COMPLETED` merely because the primary workflow works once.

---

# 32. FEATURE COMPLETION GATE

Before moving to the next feature, the agent must verify the following categories where applicable.

## A. Functional Verification

The agent must verify:

```text
[ ] The feature starts successfully
[ ] The primary user workflow works
[ ] Expected input produces expected output
[ ] Invalid input is handled safely
[ ] Error states are handled correctly
[ ] The feature does not silently fail
```

---

## B. Component Verification

Every relevant component must be checked independently.

Depending on the feature, this may include:

```text
Frontend Component
Backend Service
API Route
Business Logic
Database Operation
Background Job
Redis Operation
MinIO Operation
External API Adapter
Authentication Boundary
File Processing Module
```

The agent must not assume:

> "The complete page works, therefore every component works."

Each critical component should be independently verified.

---

# 33. MANDATORY API VERIFICATION

For every new or modified API endpoint, the agent must verify where applicable:

```text
[ ] Correct route
[ ] Correct HTTP method
[ ] Valid request handling
[ ] Invalid request handling
[ ] Required field validation
[ ] Missing field validation
[ ] Invalid type validation
[ ] Expected success response
[ ] Correct status codes
[ ] Safe error response
[ ] Database operation
[ ] Object storage operation
[ ] Background processing behavior
```

The agent should verify that the frontend and backend agree on:

```text
Request URL
HTTP Method
Headers
Authentication expectations
Request body
Response body
Status codes
Error format
```

A frontend button successfully rendering does **not** prove that its API works.

An API returning `200 OK` does **not** prove that its intended database or processing operation actually succeeded.

The agent must validate the final effect.

---

# 34. DATABASE AND STORAGE VERIFICATION

Before moving forward, any feature interacting with PostgreSQL or MinIO must verify the actual stored result.

## PostgreSQL

Verify:

```text
[ ] Expected record created or updated
[ ] Correct data stored
[ ] Relationships are correct
[ ] No unintended duplicate records
[ ] Failed operations do not create misleading partial state
```

## MinIO

Verify:

```text
[ ] Object uploaded successfully
[ ] Correct object path used
[ ] Object can be retrieved
[ ] Database reference points to correct object
[ ] Integrity verification works where applicable
```

For forensic evidence, additionally verify:

```text
Original Evidence Hash
        =
Retrieved Evidence Hash
```

when the original object is retrieved and verified.

---

# 35. INTEGRATION TESTING GATE

The agent must test how the feature interacts with the existing system.

Example:

```text
.eml Upload
    ↓
SHA-256 Calculation
    ↓
MinIO Storage
    ↓
PostgreSQL Metadata
    ↓
Analysis Job
    ↓
Background Worker
    ↓
Analysis Result
    ↓
Frontend Display
```

Testing only one step is insufficient.

The agent must verify the complete relevant chain.

Before moving forward, ask:

```text
Does data successfully enter the system?
Does every processing stage receive the correct data?
Is the result stored correctly?
Can the frontend retrieve the result?
Are failures communicated correctly?
```

---

# 36. SECURITY CHECKPOINT BEFORE NEXT FEATURE

Every meaningful feature must undergo a security review before the next major feature begins.

The depth of testing should match the feature and current development stage.

The agent must perform applicable checks for:

## Input Security

```text
[ ] Input validation
[ ] File type validation
[ ] File size validation
[ ] Malformed input handling
[ ] Unexpected input handling
```

## API Security

```text
[ ] Unsafe parameters reviewed
[ ] Injection risks considered
[ ] Error messages do not expose unnecessary internals
[ ] Sensitive operations are protected when applicable
[ ] Rate or resource abuse risk considered where relevant
```

## File Security

Especially important for MailIntel:

```text
[ ] Uploaded file type validated
[ ] File name is not blindly trusted
[ ] Unsafe file paths prevented
[ ] Malformed email structures handled safely
[ ] File processing errors do not crash the application
```

## Database Security

```text
[ ] User-controlled data is safely handled
[ ] Queries do not introduce avoidable injection risks
[ ] Sensitive data is not unnecessarily exposed
```

## Object Storage Security

```text
[ ] Object access is appropriately controlled
[ ] Sensitive object paths are not unnecessarily exposed
[ ] Temporary access mechanisms are reviewed where applicable
```

## Secret Security

```text
[ ] No API keys hardcoded
[ ] No passwords committed
[ ] Environment variables used appropriately
[ ] Logs do not expose secrets
```

---

# 37. VAPT / PENTEST CHECKPOINT

> **Important:** Every feature does not require a full production-scale penetration test after every small code change. However, every major feature must pass relevant security testing before the project moves forward.

The agent must use a **risk-based VAPT approach**.

## Level 1 — Mandatory Security Review

Required for every meaningful feature.

```text
Input validation
Error handling
Secret exposure
Basic API security
Data handling
Dependency impact
```

## Level 2 — Feature-Level Security Testing

Required when a feature introduces:

- New API endpoints
- File uploads
- Database operations
- Object storage access
- External integrations
- Sensitive data handling
- Background processing

Examples of applicable testing include:

```text
Authorization testing when authentication exists
Injection testing
Input manipulation
Malformed file testing
Path traversal testing
Unsafe object access testing
API parameter manipulation
Error handling testing
Resource exhaustion considerations
```

## Level 3 — Full Application Security Assessment

Required at major milestones, such as:

```text
Before declaring the core MVP complete
Before a major external demo
Before production deployment
After authentication and RBAC implementation
After OAuth integrations
```

The assessment should include the components that actually exist at that point.

---

# 38. SAFE VAPT RULE

Security testing must be:

- Authorized
- Performed only against systems controlled or explicitly permitted for testing
- Appropriate to the environment
- Designed to identify and remediate weaknesses

The AI agent must not perform destructive security testing that could:

- Destroy forensic evidence
- Corrupt databases
- Overload production infrastructure
- Delete user data
- Disrupt external services

Testing must preferably occur in a controlled development or staging environment.

---

# 39. SECURITY FINDING CLASSIFICATION

Security findings should be recorded as:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFORMATIONAL
```

## Critical or High Finding

The agent must normally:

```text
STOP
    ↓
Record Finding
    ↓
Assess Impact
    ↓
Fix or Contain
    ↓
Retest
```

The project should not advance past the affected feature while a known critical vulnerability remains unresolved unless the user explicitly accepts and documents the risk.

## Medium Finding

The agent should:

- Assess exploitability
- Fix where practical before advancing
- Record any deferred issue

## Low / Informational Finding

The agent should:

- Record the issue where meaningful
- Fix if practical
- Avoid blocking critical project progress unnecessarily

---

# 40. REGRESSION TEST RULE

After fixing a bug or security issue, the agent must verify:

```text
1. The original issue is fixed
2. The intended feature still works
3. Related functionality was not broken
```

Example:

```text
Fix File Validation
        ↓
Valid .eml Still Uploads
        +
Invalid File Rejected
        +
Existing Analysis Pipeline Still Works
```

A fix is incomplete if it solves one issue but breaks the feature.

---

# 41. PRE-NEXT-TASK CHECKLIST

The agent must complete the following applicable checklist before beginning the next major task.

## Functionality

```text
[ ] Core feature works
[ ] Expected workflow tested
[ ] Invalid input tested
[ ] Error handling checked
```

## Components

```text
[ ] Relevant frontend components checked
[ ] Relevant backend components checked
[ ] Business logic checked
[ ] Background processing checked
```

## APIs

```text
[ ] Each new/modified endpoint tested
[ ] Request validation checked
[ ] Response verified
[ ] Error responses checked
[ ] Final data effect verified
```

## Data

```text
[ ] Database changes verified
[ ] Object storage verified where applicable
[ ] No unexpected duplicate or corrupt records
[ ] Evidence integrity preserved
```

## Integration

```text
[ ] End-to-end relevant workflow tested
[ ] Frontend/backend integration verified
[ ] Relevant services communicate correctly
```

## Security

```text
[ ] Basic security review completed
[ ] Relevant feature-level security testing completed
[ ] No critical known vulnerability introduced
[ ] Secrets are not exposed
```

## Project State

```text
[ ] Test results recorded
[ ] Known issues recorded
[ ] Blockers recorded
[ ] Tracker.md updated
```

Only then should the agent move to the next major task.

---

# 42. DEFINITION OF VERIFIED COMPLETION

A task is **VERIFIED COMPLETED** only when:

```text
IMPLEMENTED
    +
FUNCTIONALLY TESTED
    +
COMPONENTS VERIFIED
    +
APIS VERIFIED
    +
DATA FLOW VERIFIED
    +
INTEGRATION TESTED
    +
RELEVANT SECURITY REVIEW COMPLETED
    +
CRITICAL ISSUES RESOLVED OR EXPLICITLY ACCEPTED
    +
TRACKER UPDATED
```

The agent must distinguish between:

```text
CODE COMPLETE
```

and:

```text
VERIFIED COMPLETE
```

Only `VERIFIED COMPLETE` work should normally be treated as ready for the next major development phase.

---

# 43. FINAL QUALITY GATE

Before advancing from one major phase to another, the AI agent should ask:

> **If development stopped today, would this completed feature actually work independently and safely as part of the existing MailIntel system?**

If the answer is:

```text
YES → Continue
```

If the answer is:

```text
NO → Fix, test, document, then continue
```

---

# ADDITIONAL FINAL PRINCIPLE

> **Build one feature. Verify every component. Test every relevant API. Validate the complete data flow. Perform appropriate security testing. Fix critical issues. Then move forward.**

