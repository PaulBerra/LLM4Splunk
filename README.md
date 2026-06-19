# LLM4Splunk
A custom Splunk App that bridges Splunk and a remote AI agent.



🇬🇧 English · [🇫🇷 Français](#-français)

A custom Splunk `StreamingCommand` that bridges Splunk and a remote AI agent.
The agent runs an **autonomous log investigation** by chaining SPL searches,
then returns a structured report. This script is a thin pass-through: all
investigation logic lives in the agent's server-side system prompt.

## How it works

1. Splunk passes any pipeline records to the command.
2. The command sends the request (and optional dataset) to the AI agent.
3. The agent replies with a JSON action: either a search or a diagnosis.
4. On `search`, the command runs the SPL via the Splunk REST API and returns
   the raw results to the agent.
5. The loop continues until the agent returns a `diagnose`, or the step limit
   is reached.
6. The final report is yielded as the first result row.

The agent replies only in single-line JSON:

```json
{"action":"search","query":"index=* \"PC45771\" | stats count by index, sourcetype"}
{"action":"diagnose","severity":"high","summary":"...","text":"..."}
```

<img width="2352" height="5028" alt="llm4splunk_diagram en" src="https://github.com/user-attachments/assets/8d100d1d-e2a8-4999-86d8-8dfe8fb6ce21" />


## Installation

Place the script in your app's `bin/` directory, e.g.:

```
/opt/splunk/etc/apps/LLM4Splunk/bin/LLM4Splunk.py
```

Register the command in `commands.conf` and grant it via the app's
configuration as you would for any custom search command.

## Configuration

Secrets and the endpoint are read from the environment — nothing sensitive is
hardcoded. Copy `.env.example` to `.env` and fill it in:

| Variable         | Required | Description                                   |
|------------------|----------|-----------------------------------------------|
| `LLM4Splunk_API_URL`  | yes      | AI agent completions endpoint                 |
| `LLM4Splunk_API_KEY`  | yes      | Bearer token for the AI agent                 |
| `LLM4Splunk_MODEL`    | no       | Default model name                            |

Make sure these variables are exported in the environment Splunk runs under
(for example via the app launcher or `splunk-launch.conf`).

## Usage

**Autonomous mode** — the agent investigates from scratch:

```spl
| makeresults
| LLM4Splunk incident_type="last user logged on PC di41595" max_steps=10
| table ai_rank, ai_severity, ai_summary, ai_diagnosis
```

**Pipeline mode** — feed the agent a pre-aggregated dataset:

```spl
index=netops "SW_MATM" | stats count by host, mac_address
| LLM4Splunk incident_type="root cause of mac flapping"
| table ai_rank, ai_severity, ai_summary, ai_diagnosis
```

## Parameters

| Parameter        | Required | Default        | Description                                      |
|------------------|----------|----------------|--------------------------------------------------|
| `incident_type`  | yes      | —              | The investigation request, in natural language.  |
| `entity_field`   | no       | *(empty)*      | Field used to label result rows.                 |
| `max_steps`      | no       | `10`           | Maximum search/analyze iterations.               |
| `model_name`     | no       | `LLM4Splunk_MODEL`  | Target LLM model.                                |

## Output fields

| Field          | Description                                                  |
|----------------|--------------------------------------------------------------|
| `ai_rank`      | `0 - AI ANALYSIS` for the report, then record numbering.     |
| `ai_severity`  | `critical`, `high`, `medium`, `low`, `info`.                 |
| `ai_summary`   | One-sentence summary.                                        |
| `ai_diagnosis` | Full analysis report (first row only).                       |

## Agent prompt

The investigation methodology is defined in the agent's system prompt, not in
this code. See [`agent_system_prompt.en.md`](agent_system_prompt.en.md)
([🇫🇷 FR](agent_system_prompt.fr.md)).

## Notes

- The script performs **no business validation** of queries — the agent is
  responsible for producing valid SPL.
- The time window is applied by the command; the agent must not include
  `earliest`/`latest` filters in its queries.
- When the context grows too large, the history of old searches is compressed
  (queries kept, result bodies dropped).
- Runtime logs: `tail -f $SPLUNK_HOME/log/splunk/LLM4Splunk.log`.

---

<a name="-français"></a>

# LLM4Splunk — Commande Splunk d'investigation IA

🇫🇷 Français · [🇬🇧 English](#LLM4Splunk--splunk-ai-investigation-command)

Une commande Splunk personnalisée (`StreamingCommand`) qui relie Splunk à un
agent IA distant. L'agent mène une **investigation autonome dans les logs** en
enchaînant des recherches SPL, puis rend un rapport structuré. Ce script est un
simple pass-through : toute la logique d'investigation réside dans le system
prompt de l'agent côté serveur.

## Fonctionnement

1. Splunk transmet les éventuels records du pipeline à la commande.
2. La commande envoie la demande (et le dataset optionnel) à l'agent IA.
3. L'agent répond par une action JSON : soit une recherche, soit un diagnostic.
4. Sur `search`, la commande exécute le SPL via l'API REST de Splunk et renvoie
   les résultats bruts à l'agent.
5. La boucle continue jusqu'à ce que l'agent rende un `diagnose`, ou que la
   limite d'itérations soit atteinte.
6. Le rapport final est renvoyé en première ligne des résultats.

L'agent répond uniquement en JSON sur une seule ligne :

```json
{"action":"search","query":"index=* \"PC45771\" | stats count by index, sourcetype"}
{"action":"diagnose","severity":"high","summary":"...","text":"..."}
```


<img width="2352" height="4860" alt="llm4splunk_diagram" src="https://github.com/user-attachments/assets/2f582a76-1ee3-4331-bb65-bb76e91b4a70" />![Uploading llm4splunk_diagram.en.png…]()



## Installation

Placez le script dans le répertoire `bin/` de votre app, par exemple :

```
/opt/splunk/etc/apps/LLM4Splunk/bin/LLM4Splunk.py
```

Déclarez la commande dans `commands.conf` et autorisez-la via la configuration
de l'app, comme pour toute commande de recherche personnalisée.

## Configuration

Les secrets et l'endpoint sont lus depuis l'environnement — rien de sensible
n'est codé en dur. Copiez `.env.example` vers `.env` et complétez-le :

| Variable         | Requis | Description                                    |
|------------------|--------|------------------------------------------------|
| `LLM4Splunk_API_URL`  | oui    | Endpoint de complétion de l'agent IA           |
| `LLM4Splunk_API_KEY`  | oui    | Jeton Bearer pour l'agent IA                   |
| `LLM4Splunk_MODEL`    | non    | Nom du modèle par défaut                       |

Assurez-vous que ces variables sont exportées dans l'environnement sous lequel
Splunk s'exécute (par exemple via le launcher de l'app ou `splunk-launch.conf`).

## Utilisation

**Mode autonome** — l'agent investigue depuis zéro :

```spl
| makeresults
| LLM4Splunk incident_type="dernier utilisateur connecté au PC di41595" max_steps=10
| table ai_rank, ai_severity, ai_summary, ai_diagnosis
```

**Mode pipeline** — on fournit un dataset pré-agrégé à l'agent :

```spl
index=netops "SW_MATM" | stats count by host, mac_address
| LLM4Splunk incident_type="cause racine du mac flapping"
| table ai_rank, ai_severity, ai_summary, ai_diagnosis
```

## Paramètres

| Paramètre        | Requis | Défaut         | Description                                       |
|------------------|--------|----------------|---------------------------------------------------|
| `incident_type`  | oui    | —              | La demande d'investigation, en langage naturel.   |
| `entity_field`   | non    | *(vide)*       | Champ servant à étiqueter les lignes de résultat. |
| `max_steps`      | non    | `10`           | Nombre maximum d'itérations recherche/analyse.    |
| `model_name`     | non    | `LLM4Splunk_MODEL`  | Modèle LLM ciblé.                                 |

## Champs de sortie

| Champ          | Description                                                      |
|----------------|------------------------------------------------------------------|
| `ai_rank`      | `0 - AI ANALYSIS` pour le rapport, puis numérotation des records.|
| `ai_severity`  | `critical`, `high`, `medium`, `low`, `info`.                     |
| `ai_summary`   | Résumé en une phrase.                                            |
| `ai_diagnosis` | Rapport d'analyse complet (première ligne uniquement).           |

## Prompt de l'agent

La méthode d'investigation est définie dans le system prompt de l'agent, pas
dans ce code. Voir [`agent_system_prompt.fr.md`](agent_system_prompt.fr.md)
([🇬🇧 EN](agent_system_prompt.en.md)).

## Notes

- Le script n'effectue **aucune validation métier** des requêtes — l'agent est
  responsable de produire du SPL valide.
- La fenêtre temporelle est appliquée par la commande ; l'agent ne doit pas
  inclure de filtre `earliest`/`latest` dans ses requêtes.
- En cas de dépassement du contexte, l'historique des anciennes recherches est
  compressé (requêtes conservées, résultats omis).
- Logs d'exécution : `tail -f $SPLUNK_HOME/log/splunk/LLM4Splunk.log`.
