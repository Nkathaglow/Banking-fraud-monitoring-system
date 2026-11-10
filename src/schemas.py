from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

Money = Annotated[Decimal, Field(ge=0, le=Decimal("100000000"), max_digits=18, decimal_places=2)]
Amount = Annotated[Decimal, Field(gt=0, le=Decimal("10000000"), max_digits=18, decimal_places=2)]
AccountId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{4,40}$")]


class TransactionInput(BaseModel):
    """Velocity and SIM-swap state are deliberately NOT client fields: the server derives them."""
    model_config = ConfigDict(extra="forbid")

    account_id: AccountId
    step: int = Field(ge=1, le=100000)
    amount: Amount
    oldbalanceOrg: Money
    newbalanceOrig: Money
    oldbalanceDest: Money
    newbalanceDest: Money
    type: Literal["PAYMENT", "TRANSFER", "CASH_OUT", "CASH_IN", "DEBIT"]


class SimEventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: AccountId
    event_type: Literal["SIM_SWAP", "DEVICE_CHANGE"]
    occurred_at: AwareDatetime | None = None


class DecisionResponse(BaseModel):
    """Production clients get only the first four fields. Clients configured with "verbose": true
    (developer / sandbox keys) also get the score and the reason."""
    request_id: str
    audit_id: int
    decision: Literal["APPROVE", "REVIEW", "BLOCK"]
    timestamp: datetime
    fraud_probability: float | None = None
    risk_level: str | None = None
    decision_source: str | None = None
    security_threat: str | None = None
    reason: str | None = None


# Dropdown of ready-made dummy transactions in Swagger UI (/docs). Change account_id to start a fresh history.
TRANSACTION_EXAMPLES = {
    "normal_transfer": {
        "summary": "Normal transfer (expect APPROVE)",
        "value": {"account_id": "ACC-DEMO-01", "step": 1, "amount": 5000, "oldbalanceOrg": 20000,
                  "newbalanceOrig": 15000, "oldbalanceDest": 1000, "newbalanceDest": 6000, "type": "TRANSFER"},
    },
    "payment_empties_account": {
        "summary": "Small payment that empties the account (model decides)",
        "value": {"account_id": "ACC-DEMO-02", "step": 1, "amount": 181, "oldbalanceOrg": 181,
                  "newbalanceOrig": 0, "oldbalanceDest": 0, "newbalanceDest": 0, "type": "PAYMENT"},
    },
    "full_cash_out": {
        "summary": "Cash-out of the entire balance (model decides)",
        "value": {"account_id": "ACC-DEMO-03", "step": 1, "amount": 90000, "oldbalanceOrg": 90000,
                  "newbalanceOrig": 0, "oldbalanceDest": 0, "newbalanceDest": 0, "type": "CASH_OUT"},
    },
    "ledger_mismatch": {
        "summary": "Sender balance did not drop (expect BLOCK: ledger rule)",
        "value": {"account_id": "ACC-DEMO-04", "step": 1, "amount": 5000, "oldbalanceOrg": 20000,
                  "newbalanceOrig": 20000, "oldbalanceDest": 1000, "newbalanceDest": 6000, "type": "TRANSFER"},
    },
    "very_large_transfer": {
        "summary": "250,000 in one transfer (expect REVIEW: cumulative-volume rule)",
        "value": {"account_id": "ACC-DEMO-05", "step": 1, "amount": 250000, "oldbalanceOrg": 1000000,
                  "newbalanceOrig": 750000, "oldbalanceDest": 0, "newbalanceDest": 250000, "type": "TRANSFER"},
    },
    "after_sim_swap": {
        "summary": "75,000 transfer after a SIM swap (first run the telco example for ACC-DEMO-06; expect BLOCK)",
        "value": {"account_id": "ACC-DEMO-06", "step": 1, "amount": 75000, "oldbalanceOrg": 100000,
                  "newbalanceOrig": 25000, "oldbalanceDest": 0, "newbalanceDest": 75000, "type": "TRANSFER"},
    },
}

SIM_EVENT_EXAMPLES = {
    "sim_swap": {"summary": "SIM swap for ACC-DEMO-06",
                 "value": {"account_id": "ACC-DEMO-06", "event_type": "SIM_SWAP"}},
}