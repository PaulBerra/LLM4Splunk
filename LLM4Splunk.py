#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
LLM4Splunk.py - Custom Splunk App.

Acts as a pass-through between Splunk and a remote AI agent. The agent runs an
autonomous investigation by chaining SPL searches, then returns a final report.
All investigation logic lives in the agent's server-side system prompt; this
script only executes the queries the agent requests and relays the results.

Usage (autonomous mode):
    | makeresults
    | LLM4Splunk incident_type="last user logged on PC di41595" max_steps=10
    | table ai_rank, ai_severity, ai_summary, ai_diagnosis

Usage (pipeline mode):
    index=netops "SW_MATM" | stats count by host, mac_address
    | LLM4Splunk incident_type="root cause of mac flapping"
    | table ai_rank, ai_severity, ai_summary, ai_diagnosis

Environment variables:
    LLM4Splunk_API_URL    AI agent completions endpoint (required)
    LLM4Splunk_API_KEY    Bearer token for the AI agent (required)
    LLM4Splunk_MODEL      Default model name (optional)

Runtime logs: tail -f $SPLUNK_HOME/log/splunk/LLM4Splunk.log
"""

import sys
import os
import logging
import traceback
import time
import json
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
import urllib3
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_LOG_FILE = os.path.join(os.environ.get("SPLUNK_HOME"), "log", "splunk", "LLM4Splunk.log")
log = logging.getLogger("LLM4Splunk")
log.setLevel(logging.DEBUG)
log.propagate = False
for _h in (logging.FileHandler(_LOG_FILE, mode="a", encoding="utf-8"),
           logging.StreamHandler(sys.stderr)):
    _h.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-8s [AI_INV] %(funcName)s:%(lineno)d | %(message)s",
        datefmt="%H:%M:%S"))
    log.addHandler(_h)

logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
API_URL       = os.environ.get("LLM4Splunk_API_URL", "")
API_KEY       = os.environ.get("LLM4Splunk_API_KEY", "")
DEFAULT_MODEL = os.environ.get("LLM4Splunk_MODEL", "mistral-3")

API_TIMEOUT   = 180
LLM_MAXTOK    = 4096
SPL_WINDOW    = "-24h"
SPL_MAXROWS   = 30
DATASET_MAX   = 8000
CONTEXT_MAX   = 7000
MAX_EMPTY_STREAK = int(os.environ.get("MAX_EMPTY_STREAK", 4))
# Minimal technical contract: JSON protocol only. The expert investigation
# logic is provided by the agent's own server-side system prompt.
SYSTEM_CONTRACT = (
    "You are connected to Splunk through a search tool.\n"
    "Reply STRICTLY with valid JSON, on a single line, no markdown and no surrounding text.\n\n"
    "Two possible actions:\n\n"
    "1. Run a Splunk search:\n"
    "   {\"action\":\"search\",\"query\":\"<SPL query>\"}\n"
    "   The SPL query must NOT start with the word 'search'.\n"
    "   You will receive the raw results, then you may continue.\n\n"
    "2. Produce the final report:\n"
    "   {\"action\":\"diagnose\",\"severity\":\"critical|high|medium|low|info\","
    "\"summary\":\"<one-sentence summary>\",\"text\":\"<full report>\"}\n\n"
    "No other format is accepted. No extra keys. No text outside the JSON."
)


# ---------------------------------------------------------------------------
# LLM response parsing
# ---------------------------------------------------------------------------
def _fix_json_newlines(s):
    out, in_str, esc = [], False, False
    for ch in s:
        if esc:
            out.append(ch); esc = False
        elif ch == "\\":
            out.append(ch); esc = True
        elif ch == '"':
            in_str = not in_str; out.append(ch)
        elif ch == "\n" and in_str:
            out.append("\\n")
        elif ch == "\r" and in_str:
            out.append("\\r")
        else:
            out.append(ch)
    return "".join(out)


def _extract_field(s, field):
    m = re.search(r'"' + field + r'"\s*:\s*"(.*?)"(?=\s*[,}])', s, re.DOTALL)
    if m:
        return m.group(1).replace('\\"', '"').replace("\\n", "\n").strip()
    m2 = re.search(r'"' + field + r'"\s*:\s*"(.*)', s, re.DOTALL)
    if m2:
        val = m2.group(1)
        for end_pat in [r'"\s*\}\s*$', r'"\s*,\s*"[a-z]']:
            fm = re.search(end_pat, val)
            if fm:
                val = val[:fm.start()]
                break
        return val.replace('\\"', '"').replace("\\n", "\n").strip()
    return ""


def _parse_llm(raw):
    clean = re.sub(r"```json\s*", "", raw.strip())
    clean = re.sub(r"```\s*",     "", clean).strip()

    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass

    try:
        return json.loads(_fix_json_newlines(clean))
    except json.JSONDecodeError:
        pass

    try:
        return json.loads(re.sub(r"\n\s*", " ", clean))
    except json.JSONDecodeError:
        pass

    log.warning("Unparsable JSON, falling back to manual extraction.")
    d = {}

    # Common malformation: {"action":"search","\nindex=..."}
    m_bug = re.search(r'"action"\s*:\s*"search",\s*"([^"]*(?:index=)[^"]*)"', clean, re.DOTALL)
    if m_bug:
        d["action"] = "search"
        d["query"]  = " ".join(m_bug.group(1).replace("\n", " ").split())
        return d

    m = re.search(r'"action"\s*:\s*"([^"]{1,20})"', clean)
    if m:
        d["action"] = m.group(1)

    if d.get("action") == "search":
        d["query"] = _extract_field(clean, "query")
    elif d.get("action") == "diagnose":
        d["severity"] = _extract_field(clean, "severity") or "info"
        d["summary"]  = _extract_field(clean, "summary")
        d["text"]     = _extract_field(clean, "text")

    return d if d.get("action") else {}


def _clean_report(t):
    """Strip markdown for plain-text rendering inside a Splunk cell."""
    t = t.replace("\\n", "\n")
    t = re.sub(r"#{1,4}\s*",           "",  t)
    t = re.sub(r"\*{1,3}(.*?)\*{1,3}", r"\1", t)
    t = re.sub(r"`{1,3}(.*?)`{1,3}",   r"\1", t)
    out, in_table = [], False
    for line in t.splitlines():
        s = line.strip()
        if s.startswith("|") and s.endswith("|"):
            if re.match(r"^\|[\s\-|]+\|$", s):
                in_table = True
                continue
            cells = [c.strip() for c in s.strip("|").split("|")
                     if c.strip() and not re.match(r"^[-\s]+$", c.strip())]
            if cells:
                out.append(("  " if not in_table else "  - ") + " | ".join(cells))
            in_table = True
        else:
            in_table = False
            out.append("" if re.match(r"^-{3,}$", s) else line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------
@Configuration()
class AiInvestigateCommand(StreamingCommand):
    incident_type = Option(require=True)
    entity_field  = Option(require=False, default="")
    max_steps     = Option(require=False, default="10")
    model_name    = Option(require=False, default=DEFAULT_MODEL)

    def _spl(self, query):
        """Run an SPL query through the Splunk REST export API."""
        if not query or not query.strip():
            return ["[SPL-SKIP] Empty query."]

        clean = re.sub(r"^\s*search\s+", "", query.strip(), flags=re.IGNORECASE)
        clean = " ".join(clean.split())
        full  = "search " + clean + " | head " + str(SPL_MAXROWS)

        log.info("SPL >> %s", full)

        try:
            svc  = self.service
            url  = "https://" + svc.host + ":" + str(svc.port) + "/services/search/jobs/export"
            resp = requests.post(
                url,
                headers={"Authorization": "Splunk " + svc.token},
                data={
                    "search":        full,
                    "earliest_time": SPL_WINDOW,
                    "latest_time":   "now",
                    "output_mode":   "json",
                    "count":         SPL_MAXROWS,
                },
                timeout=60,
                verify=False,
            )
            log.info("SPL << HTTP %s | %d bytes", resp.status_code, len(resp.content))

            if resp.status_code != 200:
                try:
                    msg = resp.json().get("messages", [{}])[0].get("text", resp.text[:300])
                except Exception:
                    msg = resp.text[:300]
                log.error("SPL error: %s", msg)
                return ["[SPL-ERR] " + msg]

            results = []
            for line in resp.text.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    if "result" in obj:
                        r = obj["result"]
                        results.append(str(r.get("_raw", json.dumps(r, ensure_ascii=False))))
                except json.JSONDecodeError:
                    pass

            log.info("SPL | %d result(s)", len(results))
            return results if results else ["[SPL] No results."]

        except requests.exceptions.Timeout:
            log.error("SPL timeout 60s: %s", clean[:100])
            return ["[SPL-ERR] Timeout. Simplify the query."]
        except Exception as exc:
            log.error("SPL exception: %s\n%s", exc, traceback.format_exc())
            return ["[SPL-ERR] " + str(exc)]

    def _llm(self, messages):
        """Call the AI agent with the full conversation history."""
        payload = {
            "model":      self.model_name,
            "max_tokens": LLM_MAXTOK,
            "messages":   messages,
        }
        log.info("LLM >> %d messages | last=%d chars",
                 len(messages), len(messages[-1].get("content", "")))
        t0 = time.time()
        try:
            resp = requests.post(
                API_URL,
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + API_KEY},
                json=payload,
                timeout=API_TIMEOUT,
                verify=False,
            )
            log.info("LLM << HTTP %s in %.1fs", resp.status_code, time.time() - t0)

            if resp.status_code != 200:
                log.error("LLM HTTP %s: %s", resp.status_code, resp.text[:200])
                return {"action": "diagnose", "severity": "info",
                        "summary": "API error " + str(resp.status_code),
                        "text": resp.text[:300]}

            raw_json = resp.json()
            try:
                raw = raw_json["choices"][0]["message"]["content"]
            except (KeyError, IndexError):
                raw = raw_json.get("content", "")

            log.info("LLM raw (400c):\n%s", str(raw)[:400])
            return _parse_llm(raw)

        except requests.exceptions.Timeout:
            log.error("LLM timeout %ds", API_TIMEOUT)
            return {"action": "diagnose", "severity": "info",
                    "summary": "LLM timeout",
                    "text": "No response after " + str(API_TIMEOUT) + "s."}
        except Exception as exc:
            log.error("LLM exception: %s", exc)
            return {"action": "diagnose", "severity": "info",
                    "summary": "LLM exception", "text": str(exc)}

    @staticmethod
    def _compress(messages):
        """Shrink history past CONTEXT_MAX: keep queries, drop old result bodies."""
        total = sum(len(m.get("content", "")) for m in messages)
        if total <= CONTEXT_MAX or len(messages) <= 4:
            return messages
        compressed = []
        for m in messages[1:-2]:
            c = m.get("content", "")
            if m["role"] == "user" and "Query:" in c and len(c) > 400:
                head = "\n".join(c.splitlines()[:3])
                compressed.append({"role": "user",
                                   "content": head + "\n[results omitted - context compression]"})
            else:
                compressed.append(m)
        new_msgs = [messages[0]] + compressed + messages[-2:]
        log.info("Context compressed: %d -> %d chars (%d msgs)",
                 total, sum(len(m.get("content", "")) for m in new_msgs), len(new_msgs))
        return new_msgs

    def stream(self, records):
        log.info("=" * 60)
        log.info("START | incident=%r | max_steps=%s | model=%s",
                 self.incident_type, self.max_steps, self.model_name)
        log.info("=" * 60)

        if not API_URL or not API_KEY:
            log.error("LLM4Splunk_API_URL / LLM4Splunk_API_KEY not set in environment.")
            yield {
                "ai_rank":      "0 - AI ANALYSIS",
                "ai_severity":  "info",
                "ai_summary":   "Configuration error",
                "ai_diagnosis": "LLM4Splunk_API_URL and LLM4Splunk_API_KEY environment variables must be set.",
                "host":         "[0 records]",
            }
            return

        limit = max(1, int(self.max_steps))

        # Collect pipeline records
        all_records = list(records)
        is_makeresults = (
            len(all_records) == 1
            and set(k for k in all_records[0].keys() if not k.startswith("_")) <= {"count"}
        )

        if is_makeresults or not all_records:
            log.info("Autonomous mode: no dataset.")
            all_records = []
            dataset_block = ""
        else:
            log.info("Pipeline mode: %d records.", len(all_records))
            lines = []
            for i, r in enumerate(all_records, 1):
                lines.append("Record " + str(i) + ": "
                             + json.dumps(r, ensure_ascii=False, default=str))
            dataset_block = "\n".join(lines)
            if len(dataset_block) > DATASET_MAX:
                dataset_block = dataset_block[:DATASET_MAX] + "\n...[truncated]"

        first_msg = "Engineer request: " + self.incident_type
        if dataset_block:
            first_msg += "\n\nPre-aggregated Splunk dataset:\n" + dataset_block
        else:
            first_msg += "\n\nNo dataset provided. Start the investigation from scratch."

        messages = [
            {"role": "system", "content": SYSTEM_CONTRACT},
            {"role": "user",   "content": first_msg},
        ]

        final_diag    = None
        seen_queries  = set()
        empty_streak  = 0
        

        for step in range(1, limit + 1):
            is_last = (step == limit)
            log.info("--- STEP %d/%d ---", step, limit)

            messages = self._compress(messages)

            if is_last:
                messages.append({
                    "role": "user",
                    "content": "[SYSTEM] Last iteration. You must now produce the final report with action=diagnose."
                })

            d      = self._llm(messages)
            action = d.get("action", "")
            log.info("Action: %r", action)

            if action == "search":
                query = " ".join(d.get("query", "").split())

                if re.search(r"<[^>]{1,60}>", query) and all_records and self.entity_field:
                    ev = str(all_records[0].get(self.entity_field, "")).strip()
                    if ev:
                        query = re.sub(r"<[^>]{1,60}>", ev, query)
                        log.warning("Auto-fixed placeholder -> %s", query[:80])

                if not query:
                    messages.append({"role": "assistant",
                                     "content": json.dumps(d, ensure_ascii=False)})
                    messages.append({"role": "user",
                                     "content": "[SPL-SKIP] Empty query. Run a different search."})
                    continue

                if query in seen_queries:
                    log.warning("Duplicate query: %s", query[:80])
                    messages.append({"role": "assistant",
                                     "content": json.dumps(d, ensure_ascii=False)})
                    messages.append({"role": "user",
                                     "content": "[SPL-SKIP] Query already run. Try a different one."})
                    continue

                seen_queries.add(query)
                results  = self._spl(query)
                is_err   = results[0].startswith("[SPL-ERR]")
                is_empty = results[0].startswith("[SPL] No results")
                status   = "ERROR" if is_err else "EMPTY" if is_empty else "OK (" + str(len(results)) + " rows)"

                # Force a conclusion if the agent keeps hitting nothing
                empty_streak = empty_streak + 1 if (is_err or is_empty) else 0
                if empty_streak >= MAX_EMPTY_STREAK and not is_last:
                    log.warning("4 unproductive searches in a row, forcing diagnose.")
                    messages.append({"role": "assistant",
                                     "content": json.dumps(d, ensure_ascii=False)})
                    messages.append({"role": "user",
                                     "content": "[SYSTEM] Several searches returned nothing. "
                                                "Produce the final report now with action=diagnose, "
                                                "stating what could not be found."})
                    continue

                result_text = ("Query: " + query + "\n"
                               "Status: " + status + "\n"
                               "Results:\n" + "\n".join(results))

                messages.append({"role": "assistant",
                                 "content": json.dumps(d, ensure_ascii=False)})
                messages.append({"role": "user", "content": result_text})

            elif action == "diagnose":
                final_diag = d
                log.info("DIAGNOSIS | %s | %s", d.get("severity"), d.get("summary"))
                break

            else:
                log.error("Unknown action: %r", action)
                messages.append({"role": "assistant", "content": str(d)})
                messages.append({"role": "user",
                                 "content": "[ERR] Reply only with action=search or action=diagnose as JSON."})
                if is_last:
                    final_diag = {"action": "diagnose", "severity": "info",
                                  "summary": "Unstructured response", "text": str(d)}
                    break

        if final_diag is None:
            log.warning("Max steps reached without a diagnosis.")
            final_diag = {"action": "diagnose", "severity": "info",
                          "summary": "Step limit " + str(limit) + " reached",
                          "text": "The agent did not conclude within " + str(limit) + " iterations."}

        diag_text = _clean_report(final_diag.get("text", ""))
        diag_sev  = final_diag.get("severity", "info")
        diag_sum  = final_diag.get("summary",  "")

        log.info("Report: %d chars | severity=%s", len(diag_text), diag_sev)

        row0 = {
            "ai_rank":      "0 - AI ANALYSIS",
            "ai_severity":  diag_sev,
            "ai_summary":   diag_sum,
            "ai_diagnosis": diag_text,
            "host":         "[" + str(len(all_records)) + " records]",
        }
        for r in all_records[:1]:
            for k in r.keys():
                if k not in row0:
                    row0[k] = ""
        yield row0

        for i, record in enumerate(all_records, 1):
            ev = ""
            if self.entity_field and self.entity_field in record:
                ev = " - " + str(record[self.entity_field])
            record["ai_rank"]      = str(i) + ev
            record["ai_severity"]  = diag_sev
            record["ai_summary"]   = diag_sum
            record["ai_diagnosis"] = ""
            yield record

        log.info("END | 1 report + %d records.", len(all_records))


if __name__ == "__main__":
    dispatch(AiInvestigateCommand, sys.argv, sys.stdin, sys.stdout, __name__)
