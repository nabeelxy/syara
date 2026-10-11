# 🛡️ Detection Engineering for GenAI Threats with SYara
## [un]prompted Workshop — 2 Hours

**Mohamed Nabeel, Sr. Principal Researcher, Palo Alto Networks**

---

### What You'll Build

A CTF-style workshop where you build real detection rules against real GenAI attack patterns.
Every challenge earns a **flag** (`SYARA{...}`) — collect all 8 to become a Detection Engineer.

```
🏁 Flag 1   Strings       — Catch direct prompt injections
🏁 Flag 2   Similarity    — Catch paraphrased attacks that bypass regex
🏁 Flag 3   Conditions    — Build a 3-layer ClickFix detector
🏁 Flag 4   Classifiers   — Detect brand phishing at scale
🏁 Flag 5   Fields        — Correlate endpoint events (Sigma-style)
🏁 Flag 6   Decision      — JEV structured model decisions
🏁 Flag 7   LLM + Cost    — 98% cost reduction with smart prefiltering
🏁 Flag 8   Boss Round    — Unknown threat, choose your own weapons
```

---

### Notebooks (run in order)

| Notebook | Topics | Time | Flags |
|----------|--------|------|-------|
| `00_setup.ipynb` | Environment, first match | 5 min | — |
| `01_strings_and_similarity.ipynb` | strings:, similarity:, conditions | 50 min | 1, 2, 3 |
| `02_classifiers_and_fields.ipynb` | classifier:, fields: | 30 min | 4, 5 |
| `03_decision_and_llm.ipynb` | decision: (JEV), llm: | 25 min | 6, 7 |
| `04_boss_challenge.ipynb` | Open challenge | 10 min | 8 |

---

### Setup

Open each notebook in Google Colab. All data is embedded — no downloads needed.

**For JEV (Notebook 3)**: Set your API key in the cell that asks for it.
If you don't have one, a mock evaluator runs automatically.

---

### Scoring

| Flag | Points | Challenge |
|------|--------|-----------|
| Flag 1 | 50 | Strings catch ≥80% with 0 FPs |
| Flag 2 | 100 | Similarity catches what strings missed |
| Flag 3 | 150 | ClickFix: ≥85% recall, ≤10% FPR |
| Flag 4 | 150 | Phishing: ≥80% recall, ≤5% FPR |
| Flag 5 | 100 | Endpoint: catch the attack sequence |
| Flag 6 | 200 | JEV: ≥90% accuracy on mixed threats |
| Flag 7 | 200 | LLM invocation rate ≤20% |
| Flag 8 | 300 | Boss: your call |
| **Bonus** | +50 each | Any flag earned in first 5 min of its section |
| **Total** | **1300** | |

---

### The Story

You are a detection engineer at **TechCorp**. Your AI assistant pipeline is under attack.
Attackers are evolving their techniques in real time — from simple injections to sophisticated
multi-modal campaigns. Each notebook reveals a new attack wave. Your mission: build the rules
before more damage is done.

Good luck. 🎯
