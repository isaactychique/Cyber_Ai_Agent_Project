# SENTINEL-AI LAB

**Laboratoire pratique de conception, d'attaque et de sécurisation des agents IA et des LLM.** Le projet vise une approche principalement pratique (environ 80 % de construction et d'expérimentation, 20 % de concepts) : construire des agents, reproduire des attaques dans un environnement local contrôlé, développer des défenses et mesurer leurs effets.

## Vision du projet

SENTINEL-AI LAB évolue vers une plateforme composée de six modules :

1. **Agent Arena** — agents locaux qui répondent, utilisent des outils et consultent une base documentaire.
2. **Attack Lab** — scénarios reproductibles de prompt injection, jailbreak, abus d'outils, exfiltration et empoisonnement de mémoire.
3. **AI Firewall** — inspection des entrées, sorties et appels d'outils, avec décisions explicables et règles testables.
4. **Zero Trust Control Plane** — identités d'agents, permissions minimales, autorisation à chaque action, isolation et gestion contrôlée des secrets.
5. **Detection Engine** — suivi des événements, règles de détection et détection d'actions inhabituelles ou d'escalades.
6. **Security Dashboard** — agents actifs, scénarios lancés, risques, événements, actions autorisées ou bloquées et résultats comparés.

Le résultat visé est un laboratoire où l'on peut lancer le même scénario contre un agent sans protection puis avec les défenses activées, examiner les événements et comparer les résultats.

## Architecture cible progressive

```text
Interface Streamlit
        |
API FastAPI ---- Attack Lab / scénarios
        |
Orchestrateur ---- Agents locaux via Ollama
        |
AI Firewall ---- politiques d'autorisation
        |
Outils isolés dans Docker
        |
Événements et résultats vers PostgreSQL
```

La base actuelle reste en Python, Ollama et pytest. FastAPI pourra exposer les fonctions de la plateforme, Streamlit fournir l'interface, Docker isoler les outils, PostgreSQL conserver les campagnes et événements, et OPA porter les règles lorsque la politique dépassera le besoin d'un prototype local. Redis et LangGraph seront ajoutés quand les files d'événements ou les workflows multi-agents le justifieront, pas comme dépendances initiales.

## État actuel

- Agent CLI local connecté à Ollama (`llama3.2:3b`).
- Outils `calculator`, `read_document` et `search_documents`, avec validation des arguments et restrictions de fichiers.
- Recherche plein texte locale dans les fichiers `.txt` approuvés, avec extraits bornés et classement lexical simple.
- Politique de risque par session qui réévalue chaque appel d'outil et journalise ses décisions.
- Protection heuristique de base contre certaines injections de prompts et tentatives de traversée de chemin.
- Tests unitaires et d'intégration simulant Ollama.

La première version de l'Agent Arena est en place. La recherche est lexicale et locale, pas une recherche sémantique par embeddings.

Ce dépôt ne contient pas encore l'Attack Lab scénarisé, l'API, l'isolation Docker, les identités d'agents, PostgreSQL/OPA, la détection comportementale avancée ni le dashboard. Ces éléments constituent les prochains livrables.

## Parcours pratique proposé

| Semaines | Phase | Travail | Livrable |
| --- | --- | --- | --- |
| 1–2 | Agent Arena | Stabiliser les interfaces des agents et outils, puis ajouter une recherche documentaire plus riche | Agent local avec trois outils interchangeables |
| 3–4 | Attack Lab | Décrire des attaques dans des scénarios versionnés et les rejouer automatiquement | Banc d'essai reproductible |
| 5–6 | AI Firewall | Centraliser l'inspection et les décisions avant/après modèle et avant chaque outil | Défenses configurables et auditables |
| 7–8 | Zero Trust | Définir identités, rôles, permissions minimales et isolation de l'exécution | Agents et outils séparés par privilèges |
| 9–10 | Detection Engine | Détecter séquences inhabituelles et tentatives d'escalade à partir des événements | Alertes explicables et règles testées |
| 11–12 | Dashboard et évaluation | Visualiser les campagnes et comparer agent sans protection/avec protection | Démo intégrée et rapport de résultats |

À chaque phase, conserver une expérience de référence, écrire les tests avant d'élargir les défenses et mesurer au minimum le taux de réussite des attaques, les faux positifs, les appels d'outils corrects et le temps de réponse.

## Installation et lancement actuels

Prérequis : Python 3.10 ou supérieur et Ollama.

```bash
source .venv/bin/activate
pip install -r requirements.txt
ollama pull llama3.2:3b
```

Lancer Ollama dans un terminal, puis l'agent dans un autre :

```bash
ollama serve
python main.py
```

Quitter l'agent avec `exit`.

## Sécurité actuelle et limites

La calculatrice évalue une grammaire arithmétique restreinte avec l'AST Python et rejette le code, les exposants trop grands et les valeurs non finies ou hors limites. `read_document` limite la lecture à `data/documents/`, refuse les chemins traversants, les liens symboliques vers l'extérieur et les fichiers de plus de 100 Ko. `search_documents` ne parcourt que les fichiers `.txt` directs de ce répertoire, ignore les liens symboliques et les fichiers trop volumineux, et retourne au plus cinq résultats avec trois extraits par document.

Le score de risque et les détecteurs sont heuristiques : ils ne couvrent pas toutes les formulations d'attaque. L'état est local au processus CLI et disparaît au redémarrage. Ce prototype ne fournit pas encore de véritable identité d'agent, d'isolation de processus ou de détection statistique. Il ne doit pas être présenté comme une défense complète contre les injections de prompts.

Les événements sont ajoutés à `logs/audit.jsonl`. Le journal conserve les décisions, les outils, les raisons et les scores sans enregistrer le texte des prompts.

## Tests

```bash
python -m pytest -q
```

Les tests de l'agent simulent Ollama et ne nécessitent pas de serveur LLM.
