"""Pure decision logic: rules + ML score -> APPROVE / REVIEW / BLOCK."""
from dataclasses import dataclass
from decimal import Decimal

SEVERITY = {"APPROVE": 0, "REVIEW": 1, "BLOCK": 2}
RISK = {"APPROVE": "LOW", "REVIEW": "MEDIUM", "BLOCK": "HIGH"}
TOLERANCE = Decimal("0.01")


@dataclass(frozen=True)
class Signals:
    velocity: int
    cumulative_amount: Decimal   # includes the current transaction
    sim_recently_changed: bool


@dataclass(frozen=True)
class Evaluation:
    decision: str
    risk_level: str
    decision_source: str
    security_threat: str
    message: str
    ledger_anomaly: bool
    ml_probability: float


def ledger_violations(tx) -> list[str]:
    """Hard accounting invariants, in exact Decimal arithmetic.
    Origin: balance must fall by `amount` (rise for CASH_IN).
    Destination: checked for TRANSFER only (account-to-account, both balances known);
    merchant / cash-out counterparties do not report balances."""
    problems = []
    expected_org = tx.oldbalanceOrg + tx.amount if tx.type == "CASH_IN" else tx.oldbalanceOrg - tx.amount
    if abs(tx.newbalanceOrig - expected_org) > TOLERANCE:
        problems.append("origin")
    if tx.type == "TRANSFER" and abs(tx.newbalanceDest - (tx.oldbalanceDest + tx.amount)) > TOLERANCE:
        problems.append("destination")
    return problems


def evaluate(tx, signals: Signals, ml_probability: float, settings) -> Evaluation:
    hits = []  # appended in priority order
    ledger = ledger_violations(tx)
    if ledger:
        hits.append(("BLOCK", "Ledger Invariant Violation", f"Ledger mismatch: {', '.join(ledger)}"))
    if signals.sim_recently_changed and max(tx.amount, signals.cumulative_amount) > settings.sim_swap_amount:
        hits.append(("BLOCK", "SIM-Swap Fraud", "High-value activity after recent SIM/device change"))
    if signals.velocity > settings.velocity_limit:
        hits.append(("BLOCK", "Automated Bot / Credential Stuffing",
                     f"{signals.velocity} requests in {settings.velocity_window_s}s"))
    if signals.cumulative_amount > settings.cumulative_limit:
        hits.append(("REVIEW", "Structuring / High Cumulative Volume", "Cumulative volume over limit"))

    if ml_probability >= settings.block_threshold:
        ml_decision = "BLOCK"
    elif ml_probability >= settings.review_threshold:
        ml_decision = "REVIEW"
    else:
        ml_decision = "APPROVE"

    top_rule = max(hits, key=lambda h: SEVERITY[h[0]], default=None)  # max() keeps first on ties
    rule_sev = SEVERITY[top_rule[0]] if top_rule else 0
    ml_sev = SEVERITY[ml_decision]
    final = ml_decision if ml_sev > rule_sev else (top_rule[0] if top_rule else "APPROVE")

    if top_rule and ml_sev > 0:
        source = "RULE+ML"
    elif top_rule:
        source = "RULE"
    else:
        source = "ML"

    if top_rule and rule_sev >= ml_sev:
        threat, message = top_rule[1], top_rule[2]
    elif ml_sev > 0:
        threat, message = "ML Fraud Score", f"Model score {ml_probability:.4f} >= {ml_decision.lower()} threshold"
    else:
        threat, message = "None", "No rule hit and model score below review threshold"

    return Evaluation(final, RISK[final], source, threat, message, bool(ledger), ml_probability)