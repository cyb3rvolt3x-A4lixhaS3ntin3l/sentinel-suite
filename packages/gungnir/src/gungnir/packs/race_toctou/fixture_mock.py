"""In-process fixture mock for TOCTOU / race candidate detection.

Lab-only scaffolding: shared mutable state with a check→act timing window.
No open-internet I/O. Hard request/worker/duration caps enforced by caller.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable

from gungnir.packs.race_toctou.caps import RaceCaps


@dataclass
class _CouponWindow:
    """Classic check-then-act coupon: valid once, but check/redeem raceable."""

    code: str = "LAB-COUPON"
    uses_left: int = 1
    redeem_count: int = 0
    check_delay_s: float = 0.02
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def check_valid(self) -> bool:
        time.sleep(self.check_delay_s)  # timing window
        with self._lock:
            return self.uses_left > 0

    def redeem(self) -> bool:
        with self._lock:
            if self.uses_left <= 0:
                return False
            self.uses_left -= 1
            self.redeem_count += 1
            return True

    def check_then_redeem(self) -> dict[str, Any]:
        ok = self.check_valid()
        if not ok:
            return {"ok": False, "reason": "invalid"}
        # TOCTOU gap: another worker may redeem between check and act
        redeemed = self.redeem()
        return {"ok": redeemed, "reason": "redeemed" if redeemed else "lost_race"}


@dataclass
class _BalanceWindow:
    """Check-balance-then-withdraw race window (lab mock, not real money)."""

    balance: int = 100
    withdraw_amount: int = 80
    check_delay_s: float = 0.02
    total_withdrawn: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def check_then_withdraw(self) -> dict[str, Any]:
        # TOCTOU: check balance, delay, then act — gap is raceable across workers.
        with self._lock:
            can = self.balance >= self.withdraw_amount
            seen = self.balance
        if not can:
            return {"ok": False, "balance": seen}
        time.sleep(self.check_delay_s)
        with self._lock:
            if self.balance < self.withdraw_amount:
                return {"ok": False, "balance": self.balance, "reason": "lost_race"}
            self.balance -= self.withdraw_amount
            self.total_withdrawn += self.withdraw_amount
            return {"ok": True, "balance": self.balance}


class RequestBudget:
    """Thread-safe request counter that refuses past max_requests."""

    def __init__(self, max_requests: int) -> None:
        self.max_requests = max_requests
        self._count = 0
        self._lock = threading.Lock()
        self.rejected = 0

    def try_acquire(self) -> bool:
        with self._lock:
            if self._count >= self.max_requests:
                self.rejected += 1
                return False
            self._count += 1
            return True

    @property
    def used(self) -> int:
        with self._lock:
            return self._count


def run_fixture_race(
    scenario: dict[str, Any],
    caps: RaceCaps,
    *,
    wall_clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """
    Run a capped in-process race against fixture mock state.

    Returns observation dict (never a verified finding). Caller maps to
    needs_human candidates.
    """
    now = wall_clock or time.monotonic
    started = now()
    deadline = started + caps.max_duration_s
    budget = RequestBudget(caps.max_requests)
    kind = str(scenario.get("kind") or "coupon_toctou").lower()
    name = str(scenario.get("name") or kind)
    url = str(scenario.get("url") or "http://127.0.0.1/lab/race")
    host = str(scenario.get("host") or "127.0.0.1")

    coupon: _CouponWindow | None = None
    balance: _BalanceWindow | None = None
    if kind in {"coupon_toctou", "coupon", "toctou_coupon"}:
        coupon = _CouponWindow(
            code=str(scenario.get("code") or "LAB-COUPON"),
            uses_left=int(scenario.get("uses_left") or 1),
            check_delay_s=float(scenario.get("check_delay_s") or 0.02),
        )
        worker_fn: Callable[[], dict[str, Any]] = coupon.check_then_redeem
    else:
        balance = _BalanceWindow(
            balance=int(scenario.get("balance") or 100),
            withdraw_amount=int(scenario.get("withdraw_amount") or 80),
            check_delay_s=float(scenario.get("check_delay_s") or 0.02),
        )
        worker_fn = balance.check_then_withdraw

    # Cap planned attempts to remaining budget / workers
    planned = min(caps.max_requests, max(caps.workers * 2, caps.workers))
    planned = max(1, planned)
    results: list[dict[str, Any]] = []
    timed_out = False

    def _one() -> dict[str, Any] | None:
        if now() >= deadline:
            return None
        if not budget.try_acquire():
            return None
        return worker_fn()

    with ThreadPoolExecutor(max_workers=caps.workers) as pool:
        futures = [pool.submit(_one) for _ in range(planned)]
        for fut in as_completed(futures, timeout=caps.max_duration_s + 0.5):
            if now() >= deadline:
                timed_out = True
                break
            try:
                item = fut.result(timeout=0.1)
            except Exception as exc:  # noqa: BLE001 — lab mock; record soft fail
                results.append({"ok": False, "error": type(exc).__name__})
                continue
            if item is not None:
                results.append(item)

    elapsed = now() - started
    successes = sum(1 for r in results if r.get("ok"))
    observation: dict[str, Any] = {
        "kind": kind,
        "name": name,
        "url": url,
        "host": host,
        "workers_used": caps.workers,
        "requests_used": budget.used,
        "requests_rejected_by_cap": budget.rejected,
        "max_requests": caps.max_requests,
        "max_duration_s": caps.max_duration_s,
        "elapsed_s": round(elapsed, 4),
        "timed_out": timed_out or elapsed >= caps.max_duration_s,
        "successes": successes,
        "results_count": len(results),
        "candidate_signal": False,
        "signal_reason": None,
    }

    if coupon is not None:
        observation["redeem_count"] = coupon.redeem_count
        observation["uses_left"] = coupon.uses_left
        # More redemptions than intended uses → TOCTOU candidate signal
        if coupon.redeem_count > int(scenario.get("uses_left") or 1):
            observation["candidate_signal"] = True
            observation["signal_reason"] = "coupon_over_redeem"
        elif successes > 1 and int(scenario.get("uses_left") or 1) == 1:
            # Fixture may force signal for deterministic tests
            observation["candidate_signal"] = True
            observation["signal_reason"] = "multi_success_single_use"
    if balance is not None:
        start_bal = int(scenario.get("balance") or 100)
        observation["final_balance"] = balance.balance
        observation["total_withdrawn"] = balance.total_withdrawn
        if balance.total_withdrawn > start_bal or balance.balance < 0:
            observation["candidate_signal"] = True
            observation["signal_reason"] = "over_withdraw"
        elif successes > 1:
            observation["candidate_signal"] = True
            observation["signal_reason"] = "multi_withdraw_race_window"

    # Deterministic fixture override: tests can force a signal without relying
    # on scheduler timing (still never auto-VERIFIED).
    if scenario.get("force_candidate_signal"):
        observation["candidate_signal"] = True
        observation["signal_reason"] = observation.get("signal_reason") or "fixture_forced"

    # Caps must have been respected
    assert budget.used <= caps.max_requests
    assert caps.workers <= 4
    assert elapsed <= caps.max_duration_s + 1.0  # small scheduler slack for assert

    return observation


__all__ = ["RequestBudget", "run_fixture_race"]
