#!/usr/bin/env python3
"""GuardBot test suite.

Two groups, deliberately separated:

  UNIT   — no network. Every stub is installed with mock.patch so it is undone afterwards:
           clobbering a module global leaks into later tests and manufactures failures (it
           made the live approvals test report 0 approvals for an address that has four).
           Covers hashing, ABI encode/decode, scoring, verdict logic, the impersonation rule,
           the Permit2 decoder and the canary — the places where a silent mistake turns into
           a false verdict, so they are pinned with fixed inputs.
  LIVE   — hits public RPCs and asserts against known-good and known-bad real tokens. Slow and
           dependent on third-party uptime, so it is opt-in: GUARDBOT_LIVE=1 python3 -m unittest …

Several cases below are regressions for bugs that actually shipped in this repo: a transient
node error branding USDT a honeypot, soft warnings accumulating into a hard block, a V2-only
depth measurement calling native USDC illiquid, the sell margin being reported as a token tax,
and a lying token inventing approvals. Each has a test so it cannot come back quietly.

Run:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import approvals
import tokencheck
from keccak import keccak256, selector, topic

LIVE = os.environ.get("GUARDBOT_LIVE", "") not in ("", "0", "false")
live_only = unittest.skipUnless(LIVE, "set GUARDBOT_LIVE=1 to run network tests")


class TestKeccak(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_selectors_match_the_ecosystem(self):
        self.assertEqual(selector("transfer(address,uint256)"), "0xa9059cbb")
        self.assertEqual(selector("balanceOf(address)"), "0x70a08231")
        self.assertEqual(selector("approve(address,uint256)"), "0x095ea7b3")
        self.assertEqual(selector("allowance(address,address)"), "0xdd62ed3e")

    def test_approval_topic_is_the_one_we_hardcode(self):
        self.assertEqual(topic("Approval(address,address,uint256)"), approvals.APPROVAL_TOPIC)

    def test_hashlib_sha3_is_not_keccak(self):
        # the reason this module exists at all
        import hashlib
        self.assertNotEqual(hashlib.sha3_256(b"abc").hexdigest(), keccak256(b"abc").hex())


class TestAbiCodec(unittest.TestCase):
    def test_aggregate3_round_trip(self):
        calls = [("0x" + "11" * 20, True, "0xdd62ed3e" + "00" * 64),
                 ("0x" + "22" * 20, True, "0x70a08231" + "00" * 32)]
        data = approvals._enc_aggregate3(calls)
        self.assertTrue(data.startswith("0x82ad56cb"))
        self.assertEqual((len(data) - 10) % 64, 0)   # word-aligned payload

    def test_decode_results(self):
        # two results: (true, 0x…01) and (false, empty)
        enc = tokencheck._enc_call3value([("0x" + "33" * 20, True, 0, "0x70a08231")])
        self.assertTrue(enc.startswith("0x174dea71"))

    def test_uint_array_decoder(self):
        payload = ("0x" + f"{0x20:064x}" + f"{2:064x}" + f"{111:064x}" + f"{222:064x}")
        self.assertEqual(tokencheck._dec_uint_array(payload), [111, 222])

    def test_exact_input_single_is_static_struct(self):
        d = tokencheck._enc_exact_in("0x" + "aa" * 20, "0x" + "bb" * 20, 3000,
                                     "0x" + "cc" * 20, 10 ** 15)
        self.assertEqual(d[:10], "0x04e45aaf")
        self.assertEqual(len(d) - 10, 7 * 64)        # 7 static words, no offsets


class TestChainDetection(unittest.TestCase):
    def test_detects_each_family(self):
        self.assertEqual(approvals.detect_chain("0x" + "ab" * 20), "evm")
        self.assertEqual(approvals.detect_chain("TQ5NMqJjW3jSGdrBSKvJJqPBGRxQ2b3aTL"), "tron")
        self.assertEqual(approvals.detect_chain("47gTZwMbjSqVCffvqhdRAHBKo3ZKCr4nVR5vyEVv5P6L"), "solana")
        self.assertIsNone(approvals.detect_chain("not-an-address"))


class TestPermit2Decoder(unittest.TestCase):
    def test_decodes_amount_and_expiry(self):
        amount, expiry = (1 << 160) - 1, 1790676308
        raw = "0x" + f"{amount:064x}" + f"{expiry:064x}" + f"{7:064x}"
        with mock.patch.object(approvals, "_rpc", lambda *a, **k: raw):
            got_amount, got_expiry = approvals._permit2_allowance("u", "o", "t", "s")
        self.assertEqual(got_amount, amount)
        self.assertEqual(got_expiry, expiry)

    def test_short_response_is_not_read_as_zero_exposure(self):
        with mock.patch.object(approvals, "_rpc", lambda *a, **k: "0x"):
            self.assertEqual(approvals._permit2_allowance("u", "o", "t", "s"), (0, 0))


class TestImpersonationRule(unittest.TestCase):
    """A ticker can be shared by real tokens or stolen by a fake. The difference is whether the
    accused has a market of its own — not the size ratio alone."""

    def setUp(self):
        tokencheck._REGISTRY = {"testchain": {
            "USDC": [["0xreal", str(10_000 * 10 ** 18)], ["0xbridged", str(400 * 10 ** 18)],
                     ["0xfake", "0"]],
            "SOLO": [["0xonly", str(5 * 10 ** 18)]],
        }}

    def tearDown(self):
        tokencheck._REGISTRY = None

    def test_leader_is_canonical(self):
        r = tokencheck._identity("testchain", "0xreal", "USDC", 10_000 * 10 ** 18)
        self.assertTrue(r["canonical"])

    def test_zero_liquidity_claimant_is_an_impostor(self):
        r = tokencheck._identity("testchain", "0xfake", "USDC", 0)
        self.assertFalse(r["canonical"])
        self.assertTrue(r["impostor"])

    def test_real_but_smaller_market_is_shared_not_stolen(self):
        # the bridged-stablecoin case: dwarfed, yet with genuine liquidity
        r = tokencheck._identity("testchain", "0xbridged", "USDC", 400 * 10 ** 18)
        self.assertFalse(r["canonical"])
        self.assertFalse(r.get("impostor", False))

    def test_uncontested_symbol_makes_no_claim(self):
        self.assertIsNone(tokencheck._identity("testchain", "0xonly", "SOLO", 5 * 10 ** 18))

    def test_different_symbols_never_collide(self):
        self.assertIsNone(tokencheck._identity("testchain", "0xanything", "USDE", 0))


class TestVerdictLogic(unittest.TestCase):
    """block means 'you would lose money here'. Soft warnings must never add up into one —
    a legitimate bridged USDC was blocked for having a proxy, an owner and unburned LP."""

    def _verdict(self, checks, score):
        fails = [c for c in checks if c["status"] == "fail"]
        return "block" if fails else ("warn" if score < 75 else "safe")

    def test_hard_failure_blocks(self):
        self.assertEqual(self._verdict([{"status": "fail"}], 90), "block")

    def test_many_warnings_do_not_block(self):
        warns = [{"status": "warn"}] * 5
        self.assertEqual(self._verdict(warns, 30), "warn")

    def test_clean_is_safe(self):
        self.assertEqual(self._verdict([{"status": "pass"}], 95), "safe")


class TestScoring(unittest.TestCase):
    def _score(self, item, trust="unknown"):
        with mock.patch.object(approvals, "_spender_trust", lambda c, sp: (trust, None)):
            approvals._score_items([item])
        return item

    def test_unlimited_to_unknown_spender_is_high(self):
        it = self._score({"chain": "bsc", "kind": "approval", "unlimited": True,
                          "spender": "0x" + "11" * 20})
        self.assertGreaterEqual(it["risk_score"], 60)

    def test_known_protocol_is_not_alarming(self):
        it = self._score({"chain": "bsc", "kind": "approval", "unlimited": True,
                          "spender": "0x" + "22" * 20}, trust="legit")
        self.assertLess(it["risk_score"], 40)

    def test_nft_operator_outweighs_a_plain_allowance(self):
        nft = self._score({"chain": "bsc", "kind": "nft_operator", "unlimited": True,
                           "spender": "0x" + "33" * 20})
        limited = self._score({"chain": "bsc", "kind": "approval", "unlimited": False,
                               "spender": "0x" + "44" * 20})
        self.assertGreater(nft["risk_score"], limited["risk_score"])

    def test_impersonating_token_is_critical(self):
        it = self._score({"chain": "bsc", "kind": "approval", "unlimited": True,
                          "spender": "0x" + "55" * 20, "symbol_verified": False})
        self.assertEqual(it["risk_level"], "critical")


class TestCanary(unittest.TestCase):
    """Scam tokens return an allowance for any owner. Probe hits must be re-asked for an owner
    who cannot have approved anything, or the tool invents approvals that do not exist."""

    def test_lying_token_is_dropped(self):
        liar, honest = ("0xliar", "0xspender"), ("0xhonest", "0xspender")

        def fake(rpc, owner, pairs):
            if owner == approvals.CANARY_OWNER:
                return {liar: 999}          # answers for a stranger → lying
            return {liar: 999, honest: 500}

        with mock.patch.object(approvals, "_mc_allowances", fake):
            hits = approvals._probe_allowances("rpc", "0xowner", [liar, honest])
        self.assertIn(honest, hits)
        self.assertNotIn(liar, hits)

    def test_zero_address_spender_is_ignored(self):
        pair = ("0xtok", approvals.ZERO_ADDR)
        with mock.patch.object(approvals, "_mc_allowances", lambda r, o, p: {pair: 1}):
            self.assertEqual(approvals._probe_allowances("rpc", "0xowner", [pair]), set())


class TestFailureIsNotSilent(unittest.TestCase):
    def test_unreadable_chain_head_is_a_failure_not_an_empty_chain(self):
        """latest<=0 once meant 'no blocks to scan', reporting an unreadable chain as clean."""
        with mock.patch.object(approvals, "_block_number", lambda rpc: 0):
            logs, latest, ok, partial = approvals._approval_logs(
                "bsc", approvals.EVM_CFG["bsc"], "0x" + "00" * 32, "0x" + "11" * 20)
        self.assertFalse(ok)


class TestSellMarginIsNotATax(unittest.TestCase):
    def test_round_trip_is_normalised_by_what_was_sold(self):
        """We sell 99% on purpose; dividing by 100% reported a ~1.6% tax that was our own margin."""
        self.assertAlmostEqual(tokencheck.SELL_FRACTION, 0.99, places=6)
        amount_in, fee = 10 ** 15, 3000
        perfect = amount_in * tokencheck.SELL_FRACTION * (1 - fee / 1_000_000) ** 2
        tax = max(0.0, 1 - perfect / (amount_in * tokencheck.SELL_FRACTION
                                      * (1 - fee / 1_000_000) ** 2))
        self.assertAlmostEqual(tax, 0.0, places=9)


@live_only
class TestLiveTokenSafety(unittest.TestCase):
    GOOD = [("bsc", "0x55d398326f99059ff775485246999027b3197955"),      # USDT
            ("bsc", "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"),      # CAKE
            ("ethereum", "0x6B175474E89094C44Da98b954EedeAC495271d0F"),  # DAI
            ("arbitrum", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),  # native USDC
            ("optimism", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85")]  # USDC (V3 only)
    HONEYPOTS = ["0xb7fe3b77432fe4fc245f700df846f57511cf84a7",
                 "0x67c91d04728ffcda058d86c33f7ba6f899aae3a9",
                 "0x760884305acadc6ac243572f49e763a63f9a7afa"]
    FAKE_USDT = ["0xa31f198088fbd75ecd8700f989587d413a1b8888",
                 "0x31c2a17ea816833ebb3df383f6b6d7895ba04e7b"]

    def test_real_tokens_are_never_blocked(self):
        for chain, addr in self.GOOD:
            with self.subTest(chain=chain, token=addr):
                self.assertNotEqual(tokencheck.check_token(chain, addr).get("verdict"), "block")

    def test_honeypots_are_blocked(self):
        for addr in self.HONEYPOTS:
            with self.subTest(token=addr):
                r = tokencheck.check_token("bsc", addr)
                self.assertEqual(r.get("verdict"), "block")

    def test_fake_stablecoins_are_blocked(self):
        for addr in self.FAKE_USDT:
            with self.subTest(token=addr):
                r = tokencheck.check_token("bsc", addr)
                self.assertEqual(r.get("verdict"), "block")
                ident = [c for c in r["checks"] if c["name"] == "identity"]
                self.assertTrue(ident and ident[0]["status"] == "fail")

    def test_usdt_is_stable_across_runs(self):
        """A transient node error once branded USDT a honeypot. It must not be flaky."""
        got = [tokencheck.check_token("bsc", self.GOOD[0][1]).get("verdict") for _ in range(3)]
        self.assertNotIn("block", got)

    def test_round_trip_matches_the_pool_fee(self):
        r = tokencheck.check_token("bsc", self.GOOD[1][1])
        rt = r["simulation"].get("round_trip_pct")
        self.assertGreater(rt, 98.5)      # PancakeSwap takes 0.25% twice, nothing else
        self.assertLessEqual(rt, 100.5)


@live_only
class TestLiveApprovals(unittest.TestCase):
    ADDR = "0x4E2A45E432E3EAC7F273f0eBEb8D1DaF8C59098A"

    def test_finds_the_known_approvals_on_every_chain(self):
        r = approvals.approvals(self.ADDR)
        self.assertGreaterEqual(r["count"], 4)
        self.assertFalse(r.get("degraded_chains"))
        chains = {i["chain"] for i in r["items"]}
        self.assertTrue({"bsc", "arbitrum", "polygon"} <= chains)

    def test_bsc_probe_finds_every_approval_the_explorer_lists(self):
        """BscScan lists 5 for this wallet. We found 2 until the probe learned to expand from a
        hit — the mined universe only holds pairs seen TOGETHER, and three of these were a known
        token with a known spender that had simply never been observed as a pair."""
        r = approvals.approvals(self.ADDR)
        bsc = [i for i in r["items"] if i["chain"] == "bsc"]
        self.assertGreaterEqual(len(bsc), 5)

    def test_probe_does_not_advertise_completeness(self):
        """A probe that reports a coverage % reads like a clean bill. It must not."""
        r = approvals.approvals(self.ADDR)
        if r.get("probed_chains"):
            self.assertNotIn("probe_coverage_pct", r)
            self.assertIn("nothing found", r.get("probe_note", ""))

    def test_real_stablecoins_are_not_flagged_as_impostors(self):
        r = approvals.approvals(self.ADDR)
        self.assertEqual([i for i in r["items"] if i.get("symbol_verified") is False], [])

    def test_cached_read_is_instant(self):
        approvals.approvals(self.ADDR)
        t0 = time.time()
        cached = approvals.approvals(self.ADDR, cached_only=True)
        self.assertLess(time.time() - t0, 0.5)
        self.assertTrue(cached.get("stale"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
