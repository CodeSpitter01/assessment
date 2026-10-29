# Cybersecurity Assessment — Threat Modeling & Detection Testing

Two practical assessment submissions built around a fictional student portal, **CampusLearn**.

## Selected tasks

- **Task 7 — Threat-Model a Fictional Application:** map the system, assets, trust boundaries, prioritized threats, and mitigations.
- **Task 9 — Test a Defensive Detection Rule:** test a threshold-based authentication-failure rule against synthetic logs, including boundary cases, a distributed-attempt blind spot, and a likely false positive.

The threat model and detection test are related: repeated authentication failures are one of the risks identified in Task 7 and the specific behavior exercised in Task 9.

## Repository layout

```text
cybersecurity_assessment/
├── README.md
├── SOURCES.md
├── task7/
│   └── threat_model.md
└── task9/
    ├── detection_rule.json
    ├── test_detection.py
    ├── test_plan.md
    └── data/
        ├── auth_logs.csv
        └── test_cases.json
```

## Run the detection tests

Requires Python 3.9+ and no third-party packages.

```bash
python3 task9/test_detection.py
```

The test runner reads the rule parameters from `detection_rule.json`, evaluates the synthetic CSV, prints observed alerts, and exits with a non-zero status if actual and expected outcomes differ.

## Scope and integrity notes

- CampusLearn and all authentication events are fictional and synthetic. No real credentials, people, or systems are represented.
- The detection logic is a small, portable assessment harness—not a production SIEM integration and not a claim of full Sigma compatibility.
- The threshold is a starting point for testing, not a universally correct production value. Real deployments require baseline analysis, additional context, and tuning.
- The threat model is based on stated assumptions and should be reviewed against a real system design before operational use.

## Expected result

The supplied test suite contains seven scenarios and is designed to pass all seven. Re-run the command to verify the result on your machine.
