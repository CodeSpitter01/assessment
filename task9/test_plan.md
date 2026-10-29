# Task 9 — Test a Defensive Detection Rule

**Rule:** CL-AUTH-001 — Repeated Authentication Failures from One Source IP  
**Status:** Tested against synthetic data  
**Technique context:** MITRE ATT&CK T1110 — Brute Force

## 1. Hypothesis

If at least **five failed login events from the same source IP** occur within any rolling **300-second (5-minute)** window, the rule should create an alert. The logic groups by source IP, not username, so it can represent both repeated guessing against one account and rapid failures against several accounts.

## 2. Test method

- Inputs: `data/auth_logs.csv`, a synthetic log file, plus the scenario expectations in `data/test_cases.json`.
- Fields: scenario label, UTC timestamp, source IP, username, event type, result.
- Implementation: `test_detection.py` uses Python's standard library, reads the configurable threshold/time window from `detection_rule.json`, sorts each scenario/source pair by timestamp, and checks rolling windows.
- Isolation: `test_case` is a lab-only label to keep expected scenarios independent. A production rule would group real events by time and source IP without this label.
- Reproduction: run `python3 task9/test_detection.py` from the repository root or invoke the script by path.

## 3. Test cases and expected behavior

| ID | Scenario | Expected | Reason |
|---|---|---|---|
| TC01 | Normal success + one failure | No alert | Does not approach threshold |
| TC02 | Four failures in five minutes | No alert | One below threshold |
| TC03 | Five rapid failures against one account | Alert | Threshold reached within window |
| TC04 | Five rapid failures across five accounts from one IP | Alert | Can surface password-spraying-like behavior |
| TC05 | Five failures spread across eight minutes | No alert | No rolling five-minute window reaches five |
| TC06 | Four failures from each of two IPs | No alert | Exposes the rule's per-IP distributed-attempt blind spot |
| TC07 | Five failures behind a shared NAT | Alert | Demonstrates a likely benign/ambiguous trigger requiring triage |

## 4. Results

The reproducible test run is expected to pass all seven assertions. The script prints actual outcomes and the alerts it generated. Record or screenshot the output after running the command on the submission machine.

### Interpretation

- **Detection behavior:** the threshold rule catches rapid repeated failures from one source IP in TC03, TC04, and TC07.
- **Boundary behavior:** TC02 and TC05 do not alert, demonstrating threshold and time-window behavior.
- **Known blind spot:** TC06 does not alert because neither source IP independently reaches five failures. Add complementary user-centric or broader correlation logic before relying on this rule operationally.
- **False-positive risk:** TC07 deliberately alerts on a shared address; an alert is a signal to investigate, not proof of attack.

## 5. Proposed improvements

1. Correlate with successful authentication soon after repeated failures, while accounting for legitimate sign-ins.
2. Add a separate user-centric detection for failures against one account across multiple IPs and a source-centric detection for attempts against many accounts.
3. Enrich with device, known corporate egress/NAT, and identity-provider risk signals where available.
4. Baseline normal failures and tune alert thresholds on real telemetry before deployment.
5. In the response playbook, inspect affected accounts and source context, validate whether any login succeeded, apply proportionate controls, and preserve the related events.

## 6. Limitations

This test does not use a live SIEM, production log schema, a vendor-specific query language, or real traffic. The rule logic is a deliberately small portable harness and is not represented as a drop-in production Sigma rule. All IP addresses and accounts are synthetic/documentation examples. The test evaluates the rule's defined behavior, not its real-world precision or recall.

## 7. References

See [`../SOURCES.md`](../SOURCES.md). MITRE ATT&CK T1110 provides the technique context; Sigma documentation informs the general practice of documenting detection logic and known false positives.
