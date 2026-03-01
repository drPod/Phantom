"""Wallet resolver: Etherscan (ETH) and Blockchain.com (BTC) for balance, transactions, and counterparty discovery."""

import logging
import os
import time
import uuid
from typing import Any

import httpx
import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from scan_log import log_scan_event
from stream import write_stream_event

logger = logging.getLogger(__name__)

SOURCE = "wallet_resolver"

# Maximum counterparty wallet addresses to emit as new entities per resolver call
_MAX_COUNTERPARTIES = 5

# Etherscan free tier: 3 calls/sec — sleep between sequential calls
_ETHERSCAN_SLEEP = 0.4


def _entity_key(etype: str, value: str) -> str:
    v = (str(value) if not isinstance(value, str) else value).strip().lower()
    return f"{etype}:{v}"


def _backoff(attempt: int, retry_after: int | None = None) -> None:
    if retry_after and retry_after > 0:
        time.sleep(min(retry_after, 60))
    else:
        time.sleep(min(2**attempt, 60))


def _is_eth_address(addr: str) -> bool:
    return addr.startswith("0x") and len(addr) == 42


def _is_btc_address(addr: str) -> bool:
    return addr.startswith(("1", "3", "bc1"))


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=10)
def resolve_wallet(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    scan_id: str = "",
) -> None:
    """Resolve a cryptocurrency wallet address via Etherscan (ETH) or Blockchain.com (BTC)."""
    if not scan_id:
        return
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
    if "stop" in d:
        return

    address = (entity_value or "").strip()
    if not address:
        return

    node_id = _entity_key(EntityType.WALLET.value, address)
    metadata: dict[str, Any] = {"address": address}
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id, "relationship": "resolved_wallet", "confidence": 1.0}
    ]
    to_push: list[dict[str, Any]] = []

    is_eth = _is_eth_address(address)
    is_btc = _is_btc_address(address)

    # If neither pattern matches, attempt both
    if not is_eth and not is_btc:
        is_eth = True
        is_btc = True

    # -------------------------------------------------------------------------
    # Ethereum via Etherscan
    # -------------------------------------------------------------------------
    if is_eth:
        etherscan_key = os.environ.get("ETHERSCAN_KEY", "")
        if etherscan_key:
            base_params = {
                "chainid": "1",
                "module": "account",
                "apikey": etherscan_key,
                "address": address,
            }

            # 1a. ETH balance
            for attempt in range(3):
                try:
                    r = httpx.get(
                        "https://api.etherscan.io/v2/api",
                        params={**base_params, "action": "balance", "tag": "latest"},
                        timeout=15,
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if data.get("status") == "1":
                            wei = int(data.get("result", 0))
                            metadata["eth_balance_wei"] = wei
                            metadata["eth_balance_eth"] = round(wei / 10**18, 8)
                        elif data.get("message") not in ("No transactions found", "No records found"):
                            logger.warning("Etherscan balance error for %s: %s", address, data.get("message"))
                            log_scan_event(
                                scan_id,
                                "resolver_failed",
                                resolver="resolve_wallet",
                                entity_key=node_id,
                                error=str(data.get("message")),
                                service="Etherscan balance",
                                response_preview=str(data)[:500],
                            )
                    elif r.status_code == 429:
                        retry_after = int(r.headers.get("Retry-After", 0) or 0)
                        _backoff(attempt, retry_after or 10)
                        continue
                    else:
                        response_preview = (r.text or "")[:500]
                        logger.warning("Etherscan balance status %s for %s: %s", r.status_code, address, response_preview)
                        log_scan_event(
                            scan_id,
                            "resolver_failed",
                            resolver="resolve_wallet",
                            entity_key=node_id,
                            error=f"Etherscan balance status {r.status_code}",
                            service="Etherscan balance",
                            response_preview=response_preview,
                        )
                    break
                except Exception as e:
                    response_preview = (getattr(getattr(e, "response", None), "text", None) or "")[:500]
                    logger.warning("Etherscan balance failed for %s (attempt %s): %s", address, attempt + 1, e)
                    log_scan_event(
                        scan_id,
                        "resolver_failed",
                        resolver="resolve_wallet",
                        entity_key=node_id,
                        error=str(e),
                        service="Etherscan balance",
                        response_preview=response_preview,
                    )
                    _backoff(attempt)

            time.sleep(_ETHERSCAN_SLEEP)

            # 1b. Normal transactions (last 10, descending)
            for attempt in range(3):
                try:
                    r = httpx.get(
                        "https://api.etherscan.io/v2/api",
                        params={
                            **base_params,
                            "action": "txlist",
                            "startblock": "0",
                            "endblock": "99999999",
                            "page": "1",
                            "offset": "10",
                            "sort": "desc",
                        },
                        timeout=20,
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if data.get("status") == "1":
                            txs = data.get("result", [])
                            metadata["eth_tx_count"] = len(txs)
                            metadata["eth_recent_txs"] = [
                                {
                                    "hash": tx.get("hash"),
                                    "from": tx.get("from"),
                                    "to": tx.get("to"),
                                    "value_wei": tx.get("value"),
                                    "value_eth": round(int(tx.get("value", 0)) / 10**18, 8),
                                    "timestamp": tx.get("timeStamp"),
                                    "is_error": tx.get("isError") == "1",
                                }
                                for tx in txs
                            ]
                            # Discover counterparty wallets
                            seen_counterparties: set[str] = set()
                            for tx in txs:
                                for field in ("from", "to"):
                                    cp = (tx.get(field) or "").strip().lower()
                                    if cp and cp != address.lower() and cp not in seen_counterparties:
                                        seen_counterparties.add(cp)
                                        if len(seen_counterparties) <= _MAX_COUNTERPARTIES:
                                            cp_key = _entity_key(EntityType.WALLET.value, cp)
                                            to_push.append({
                                                "type": EntityType.WALLET.value,
                                                "value": cp,
                                                "source": SOURCE,
                                                "confidence": 0.7,
                                                "depth": depth + 1,
                                                "parent_key": node_id,
                                            })
                                            edges_batch.append({
                                                "source": node_id,
                                                "target": cp_key,
                                                "relationship": "eth_transaction",
                                                "confidence": 0.7,
                                            })
                        elif data.get("message") not in ("No transactions found", "No records found"):
                            logger.warning("Etherscan txlist error for %s: %s", address, data.get("message"))
                    elif r.status_code == 429:
                        retry_after = int(r.headers.get("Retry-After", 0) or 0)
                        _backoff(attempt, retry_after or 10)
                        continue
                    break
                except Exception as e:
                    response_preview = (getattr(getattr(e, "response", None), "text", None) or "")[:500]
                    logger.warning("Etherscan txlist failed for %s (attempt %s): %s", address, attempt + 1, e)
                    log_scan_event(
                        scan_id,
                        "resolver_failed",
                        resolver="resolve_wallet",
                        entity_key=node_id,
                        error=str(e),
                        service="Etherscan txlist",
                        response_preview=response_preview,
                    )
                    _backoff(attempt)

            time.sleep(_ETHERSCAN_SLEEP)

            # 1c. ERC-20 token transfers (last 10, descending)
            for attempt in range(3):
                try:
                    r = httpx.get(
                        "https://api.etherscan.io/v2/api",
                        params={
                            **base_params,
                            "action": "tokentx",
                            "startblock": "0",
                            "endblock": "99999999",
                            "page": "1",
                            "offset": "10",
                            "sort": "desc",
                        },
                        timeout=20,
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if data.get("status") == "1":
                            transfers = data.get("result", [])
                            metadata["eth_token_transfers"] = [
                                {
                                    "hash": t.get("hash"),
                                    "from": t.get("from"),
                                    "to": t.get("to"),
                                    "token_name": t.get("tokenName"),
                                    "token_symbol": t.get("tokenSymbol"),
                                    "value": t.get("value"),
                                    "token_decimal": t.get("tokenDecimal"),
                                    "timestamp": t.get("timeStamp"),
                                }
                                for t in transfers
                            ]
                        elif data.get("message") not in ("No transactions found", "No records found"):
                            logger.warning("Etherscan tokentx error for %s: %s", address, data.get("message"))
                    elif r.status_code == 429:
                        retry_after = int(r.headers.get("Retry-After", 0) or 0)
                        _backoff(attempt, retry_after or 10)
                        continue
                    break
                except Exception as e:
                    response_preview = (getattr(getattr(e, "response", None), "text", None) or "")[:500]
                    logger.warning("Etherscan tokentx failed for %s (attempt %s): %s", address, attempt + 1, e)
                    log_scan_event(
                        scan_id,
                        "resolver_failed",
                        resolver="resolve_wallet",
                        entity_key=node_id,
                        error=str(e),
                        service="Etherscan tokentx",
                        response_preview=response_preview,
                    )
                    _backoff(attempt)

    # -------------------------------------------------------------------------
    # Bitcoin via Blockchain.com (no API key required)
    # -------------------------------------------------------------------------
    if is_btc:
        # Blockchain.com rate limit: 1 req/10 sec; be conservative
        try:
            r = httpx.get(
                f"https://blockchain.info/rawaddr/{address}",
                params={"limit": "10"},
                timeout=20,
                headers={"User-Agent": "osint-recon/1.0"},
            )
            if r.status_code == 200:
                data = r.json()
                satoshi = data.get("final_balance", 0)
                metadata["btc_balance_satoshi"] = satoshi
                metadata["btc_balance_btc"] = round(satoshi / 10**8, 8)
                metadata["btc_n_tx"] = data.get("n_tx", 0)
                metadata["btc_total_received"] = data.get("total_received", 0)
                metadata["btc_total_sent"] = data.get("total_sent", 0)

                txs = data.get("txs", [])
                metadata["btc_recent_txs"] = [
                    {
                        "hash": tx.get("hash"),
                        "time": tx.get("time"),
                        "result": tx.get("result"),
                        "balance": tx.get("balance"),
                    }
                    for tx in txs[:10]
                ]

                # Discover counterparty addresses from inputs and outputs
                seen_counterparties: set[str] = set()
                for tx in txs:
                    for inp in tx.get("inputs", []):
                        cp = (inp.get("prev_out", {}).get("addr") or "").strip()
                        if cp and cp != address and cp not in seen_counterparties:
                            seen_counterparties.add(cp)
                            if len(seen_counterparties) <= _MAX_COUNTERPARTIES:
                                cp_key = _entity_key(EntityType.WALLET.value, cp)
                                to_push.append({
                                    "type": EntityType.WALLET.value,
                                    "value": cp,
                                    "source": SOURCE,
                                    "confidence": 0.7,
                                    "depth": depth + 1,
                                    "parent_key": node_id,
                                })
                                edges_batch.append({
                                    "source": node_id,
                                    "target": cp_key,
                                    "relationship": "btc_transaction",
                                    "confidence": 0.7,
                                })
                    for out in tx.get("out", []):
                        cp = (out.get("addr") or "").strip()
                        if cp and cp != address and cp not in seen_counterparties:
                            seen_counterparties.add(cp)
                            if len(seen_counterparties) <= _MAX_COUNTERPARTIES:
                                cp_key = _entity_key(EntityType.WALLET.value, cp)
                                to_push.append({
                                    "type": EntityType.WALLET.value,
                                    "value": cp,
                                    "source": SOURCE,
                                    "confidence": 0.7,
                                    "depth": depth + 1,
                                    "parent_key": node_id,
                                })
                                edges_batch.append({
                                    "source": node_id,
                                    "target": cp_key,
                                    "relationship": "btc_transaction",
                                    "confidence": 0.7,
                                })
            elif r.status_code == 404:
                metadata["btc_not_found"] = True
            elif r.status_code == 429:
                logger.warning("Blockchain.com rate limited for %s", address)
                log_scan_event(
                    scan_id,
                    "resolver_failed",
                    resolver="resolve_wallet",
                    entity_key=node_id,
                    error="Blockchain.com rate limited (429)",
                    service="Blockchain.com",
                )
            else:
                response_preview = (r.text or "")[:500]
                logger.warning("Blockchain.com status %s for %s: %s", r.status_code, address, response_preview)
                log_scan_event(
                    scan_id,
                    "resolver_failed",
                    resolver="resolve_wallet",
                    entity_key=node_id,
                    error=f"Blockchain.com status {r.status_code}",
                    service="Blockchain.com",
                    response_preview=response_preview,
                )
        except Exception as e:
            response_preview = (getattr(getattr(e, "response", None), "text", None) or "")[:500]
            logger.warning("Blockchain.com failed for %s: %s", address, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_wallet",
                entity_key=node_id,
                error=str(e),
                service="Blockchain.com",
                response_preview=response_preview,
            )

    # Write counterparty wallet nodes discovered during this call
    for cp_info in to_push:
        cp_key = _entity_key(EntityType.WALLET.value, cp_info["value"])
        cp_payload = {
            "id": cp_key,
            "type": EntityType.WALLET.value,
            "value": cp_info["value"],
            "metadata": {"address": cp_info["value"]},
            "depth": cp_info["depth"],
        }
        d[f"{NODE_PREFIX}{cp_key}"] = cp_payload
        write_stream_event(scan_id, "node", cp_payload)

    # Write primary node
    node_payload = {
        "id": node_id,
        "type": EntityType.WALLET.value,
        "value": address,
        "metadata": metadata,
        "depth": depth,
    }
    d[f"{NODE_PREFIX}{node_id}"] = node_payload
    write_stream_event(scan_id, "node", node_payload)

    d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch
    for edge in edges_batch:
        write_stream_event(scan_id, "edge", edge)
