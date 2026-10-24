"""Multilingual detection lexicon.

Each entry is ``(pattern, confidence, evidence)``. Patterns run on the
normalized analysis view (casefolded, diacritics stripped, homoglyphs mapped),
so they are written in lowercase ASCII.

``confidence`` is a heuristic weight chosen by the authors to rank how
specific a pattern is to an attack (0.5 = generic wording that also appears in
benign text, 0.9 = wording that is rarely benign). It is NOT a calibrated
probability; the benchmark in ``backend/benchmark`` measures actual error rates.

To support a new language, add a key (e.g. ``"es"``) under each category. The
detectors iterate over every language, so no other code change is required.
"""

# Tools whose explicit mention together with bypass wording is suspicious.
# test_lexicon_covers_registry keeps this list in sync with the tool registry.
KNOWN_TOOLS = (
    "get_my_schedule",
    "get_my_courses",
    "get_course_students",
    "read_course_note",
    "search_student",
    "search_professor",
    "get_room_schedule",
    "find_free_room",
    "update_schedule",
)
_TOOLS = "|".join(KNOWN_TOOLS) + r"|change_role|grant_\w+|delete_\w+|drop_\w+|exec\w*|shell"

LEXICON: dict[str, dict[str, list[tuple[str, float, str]]]] = {
    "instruction_override": {
        "en": [
            (
                r"\b(ignore|disregard|forget|skip|override|overrule|bypass|abandon|drop)\b"
                r"[^.!?\n]{0,50}\b(instructions?|rules|directives?|guidelines|system prompt"
                r"|constraints|polic(?:y|ies)|programming|guardrails?)\b",
                0.9,
                "attempt to discard the assistant's instructions",
            ),
            (
                r"\b(do not|don't|stop|no longer)\s+(follow|obey|apply|respect)(ing)?\b"
                r"[^.!?\n]{0,30}\b(instructions?|rules|guidelines|system|policy)\b",
                0.85,
                "attempt to stop the assistant from following its rules",
            ),
            (
                r"\b(your|the|all)\s+(previous|prior|original|initial|old)\s+"
                r"(instructions?|rules)\s+(are|is|have been)\s+"
                r"(void|cancel+ed|revoked|obsolete|replaced|no longer valid)",
                0.9,
                "claim that prior instructions were revoked",
            ),
            (
                r"\b(new|updated|real|actual|true)\s+(instructions?|rules|system prompt"
                r"|directives?)\s*(:|are|follow)",
                0.75,
                "injection of replacement instructions",
            ),
            (
                r"\bfrom now on\b[^.!?\n]{0,40}\byou\b[^.!?\n]{0,30}"
                r"\b(will|must|are|should|answer|respond|ignore|only)\b",
                0.65,
                "attempt to redefine assistant behaviour for the session",
            ),
            (
                r"\b(these|this|my) instructions? (take|takes|have|has) (precedence|priority)"
                r"|\b(highest|top|maximum) priority (instruction|override|directive)"
                r"|\b(system|admin|developer|security) override\b",
                0.85,
                "instruction hierarchy manipulation",
            ),
        ],
        "fr": [
            (
                r"\b(ignore[sz]?|oublie[sz]?|ne tiens? (pas|plus) compte|ne respecte[sz]? "
                r"(pas|plus)|outrepasse[sz]?|contourne[sz]?|fais abstraction|annule[sz]?)\b"
                r"[^.!?\n]{0,50}\b(instructions?|regles|consignes?|directives?|prompt"
                r"|contraintes|politiques?|restrictions)\b",
                0.9,
                "tentative d'ecarter les instructions de l'assistant",
            ),
            (
                r"\b(tes|vos|les) (anciennes |precedentes |premieres )?(instructions|regles"
                r"|consignes) (sont|ne sont plus) (annulees|obsoletes|caduques|valables"
                r"|remplacees)",
                0.9,
                "affirmation que les instructions precedentes sont annulees",
            ),
            (
                r"\b(nouvelles?|vraies?|veritables?)\s+(instructions?|regles|consignes?)"
                r"\s*(:|sont)",
                0.75,
                "injection d'instructions de remplacement",
            ),
            (
                r"\ba partir de maintenant\b[^.!?\n]{0,40}\b(tu|vous)\b",
                0.6,
                "tentative de redefinir le comportement de l'assistant",
            ),
            (
                r"\b(ces|cette|mes) (instructions?|consignes?) (sont|est) prioritaires?"
                r"|\bpriorite (absolue|maximale) (sur|aux?)\b",
                0.8,
                "manipulation de la hierarchie des instructions",
            ),
        ],
    },
    "role_manipulation": {
        "en": [
            (
                r"\b(i am|i'm|im|as an?|as the)\s+(an?\s+|the\s+)?(admin|administrator|root"
                r"|superuser|sysadmin|professor|teacher|developer of this|your (developer"
                r"|creator|owner))\b",
                0.85,
                "claimed identity or role in the prompt",
            ),
            (
                r"\b(you are now|you're now|act as|pretend (to be|you are)|behave as"
                r"|roleplay as|switch to)\b[^.!?\n]{0,30}\b(admin|administrator|root"
                r"|superuser|developer mode|unrestricted|system)\b",
                0.85,
                "attempt to assign a privileged persona",
            ),
            (
                r"\b(grant|give|assign|elevate|escalate|upgrade|promote)\b[^.!?\n]{0,30}"
                r"\b(me|my account|my role|my privileges|my permissions)\b[^.!?\n]{0,30}"
                r"\b(admin|administrator|root|privileges?|permissions?|role|access)\b",
                0.9,
                "privilege escalation request",
            ),
            (
                r"\b(change|set|switch|update)\b[^.!?\n]{0,15}\bmy role\b",
                0.9,
                "request to change the authenticated role",
            ),
            (
                r"\b(admin|administrator|god|debug|maintenance|sudo)\s+mode\b",
                0.75,
                "request for a privileged mode",
            ),
        ],
        "fr": [
            (
                r"\b(je suis|moi c'?est|en tant qu'?)\s*(un |une |le |la |l')?(admin"
                r"|administrateur|administratrice|root|superutilisateur|professeur"
                r"|enseignant|developpeur)\b",
                0.85,
                "identite ou role revendique dans le prompt",
            ),
            (
                r"\b(tu es|vous etes|agis|agissez|fais comme si tu etais|comporte-toi"
                r"|joue le role)\b[^.!?\n]{0,30}\b(admin|administrateur|root"
                r"|sans restriction|developpeur|systeme)\b",
                0.85,
                "tentative d'attribuer un personnage privilegie",
            ),
            (
                r"\b(donne|accorde|attribue|eleve|passe|mets?)\b[^.!?\n]{0,30}"
                r"\b(droits?|privileges?|role|acces|permissions?)\b[^.!?\n]{0,30}"
                r"\b(admin|administrateur|root|complets?|eleves?|total)",
                0.9,
                "demande d'elevation de privileges",
            ),
            (
                r"\b(change|modifie|mets?)\b[^.!?\n]{0,10}\bmon role\b",
                0.9,
                "demande de changement du role authentifie",
            ),
            (
                r"\bmode (admin|administrateur|developpeur|debug|maintenance|dieu"
                r"|sans restriction)\b",
                0.75,
                "demande d'un mode privilegie",
            ),
        ],
    },
    "jailbreak": {
        "en": [
            (
                r"\b(disable|deactivate|turn off|remove|bypass|switch off|circumvent|lift)\b"
                r"[^.!?\n]{0,30}\b(safety|safeguards?|guardrails?|filters?|restrictions"
                r"|protections?|content policy|moderation|censorship)\b",
                0.85,
                "attempt to disable safeguards",
            ),
            (
                r"\b(without|no|free of|free from|unrestricted by)\s+(any\s+)?(rules"
                r"|restrictions|limits|limitations|filters|censorship|guidelines"
                r"|safeguards|guardrails|ethics)\b",
                0.7,
                "request to operate without restrictions",
            ),
            (
                r"\b(restrictions?|rules|filters?|safeguards?|guardrails?)\b[^.!?\n]{0,30}"
                r"\b(are|were|have been)\s+(lifted|disabled|removed|suspended|off)\b",
                0.85,
                "claim that safeguards are disabled",
            ),
            (
                r"\b(evil|unfiltered|uncensored|unrestricted|jailbroken)\s+(ai|assistant"
                r"|mode|version|model|persona)\b",
                0.85,
                "request for an unrestricted persona",
            ),
        ],
        "fr": [
            (
                r"\b(desactive\w*|supprime\w*|retire\w*|contourne\w*|leve\w*|enleve\w*"
                r"|coupe\w*)\b[^.!?\n]{0,30}\b(securite|filtres?|restrictions?|garde-?fous"
                r"|protections?|regles|limitations?|moderation|censure)\b",
                0.85,
                "tentative de desactiver les protections",
            ),
            (
                r"\b(restrictions?|regles|filtres?|garde-?fous|limitations?|protections?)"
                r"\b[^.!?\n]{0,40}\b(desactivee?s?|levees?|supprimees?|suspendues?"
                r"|n'existent plus)\b",
                0.85,
                "affirmation que les protections sont desactivees",
            ),
            (
                r"\bsans (aucune |aucun )?(regles?|restrictions?|limites?|filtres?|censure"
                r"|garde-?fous|limitations?)\b",
                0.7,
                "demande d'agir sans restrictions",
            ),
            (
                r"\b(ia|assistant|mode|version) (non censuree?|sans filtres?|debridee?)",
                0.85,
                "demande d'un personnage sans restriction",
            ),
        ],
    },
    "sensitive_information": {
        "en": [
            (
                r"\b(show|reveal|print|display|output|repeat|give|tell|share|leak|dump"
                r"|disclose|list|what (is|are|were))\b[^.!?\n]{0,40}\b(system|initial"
                r"|hidden|internal|original|developer|secret)\s*(prompt|instructions?"
                r"|message|rules|configuration|config)\b",
                0.9,
                "system prompt extraction attempt",
            ),
            (
                r"\b(repeat|print|output|copy|show)\b[^.!?\n]{0,30}\b(everything|all|the text"
                r"|the words|verbatim)\b[^.!?\n]{0,30}\b(above|before|preceding|so far"
                r"|earlier)\b",
                0.85,
                "request to echo hidden context",
            ),
            (
                r"\b(what|which|how) (were|are|have) you (been )?(told|instructed"
                r"|programmed|configured)\b",
                0.7,
                "probing of hidden instructions",
            ),
            (
                r"\b(the|your|their|his|her|all|admin\w*|users?'?|other users?'?"
                r"|students?'?|professors?'?|server|database|db|system|gemini|google"
                r"|backend|stored)\b[^.!?\n]{0,20}\b(api[\s_-]?keys?|secret[\s_-]?keys?"
                r"|access tokens?|jwt[\s_-]?secret|passwords?|password hash(es)?"
                r"|hashed_password|credentials|private keys?|\.env\b|environment variables)",
                0.85,
                "request for credentials or secrets",
            ),
            (
                r"\b(private|personal|confidential|sensitive|home)\s+(data|information|info"
                r"|details|records|addresses|phone numbers?|files?|salar(y|ies)|grades)\b",
                0.8,
                "request for private or confidential data",
            ),
            (
                r"\b(all|every|other)\s+(the\s+)?(students?|users?|professors?|staff)'?s?"
                r"\b[^.!?\n]{0,30}\b(emails?|phones?|addresses|passwords?|grades|records)",
                0.75,
                "bulk request for personal data",
            ),
        ],
        "fr": [
            (
                r"\b(montre\w*|affiche\w*|revele\w*|donne\w*|imprime\w*|repete\w*|copie\w*"
                r"|ecris|dis|partage\w*|liste\w*|divulgue\w*|quel(le)?s? (est|sont))\b"
                r"[^.!?\n]{0,40}\b(prompt|instructions?|consignes?|regles|configuration)"
                r"\s*(systeme|initiale?s?|internes?|cachees?|secretes?|d'origine)\b",
                0.9,
                "tentative d'extraction du prompt systeme",
            ),
            (
                r"\b(montre\w*|affiche\w*|revele\w*|donne\w*)\b[^.!?\n]{0,30}"
                r"\b(prompt systeme|system prompt)\b",
                0.9,
                "tentative d'extraction du prompt systeme",
            ),
            (
                r"\b(repete\w*|recopie\w*|affiche\w*|imprime\w*)\b[^.!?\n]{0,30}\b(tout"
                r"|texte|mots)\b[^.!?\n]{0,30}\b(ci-dessus|au-dessus|precedent|avant)\b",
                0.85,
                "demande de reproduire le contexte cache",
            ),
            (
                r"\b(le|la|les|ton|ta|tes|son|sa|ses|leurs?|de l'admin\w*|des utilisateurs"
                r"|des etudiants|des professeurs|du serveur|de la base|du systeme)\b"
                r"[^.!?\n]{0,25}\b(cles? api|api[\s_-]?keys?|cles? secretes?|jetons?"
                r"|tokens?|mots? de passe|identifiants|secrets?|\.env\b"
                r"|variables d'environnement)",
                0.85,
                "demande d'identifiants ou de secrets",
            ),
            (
                r"\b(donnees|informations?|infos|details|dossiers?|coordonnees|adresses"
                r"|numeros?|notes|salaires?)\s+(privees?|personnelles?|confidentielles?"
                r"|sensibles?)\b",
                0.85,
                "demande de donnees privees ou confidentielles",
            ),
            (
                r"\b(tous|toutes|chaque|les autres)\s+(les\s+)?(etudiants|utilisateurs"
                r"|professeurs|enseignants)\b[^.!?\n]{0,30}\b(e-?mails?|courriels?"
                r"|telephones?|adresses|mots de passe|notes)",
                0.75,
                "demande massive de donnees personnelles",
            ),
        ],
    },
    "tool_manipulation": {
        "en": [
            (
                r"\b(without|skip(ping)?|bypass(ing)?|no need for|avoid(ing)?"
                r"|don'?t (ask|wait) for)\b[^.!?\n]{0,25}\b(approval|validation"
                r"|confirmation|review|human|authori[sz]ation|permission checks?"
                r"|tool guard|rbac)\b",
                0.9,
                "attempt to bypass approval or authorization",
            ),
            (
                r"\b(auto-?(matically)?[- ]?approve|approve (it|this|the request) "
                r"(yourself|automatically)|mark (it|this|the request) as approved"
                r"|status\s*[:=]\s*\"?approved|approved\s*[:=]\s*true)\b",
                0.85,
                "attempt to self-approve a sensitive action",
            ),
            (
                rf"\b(call|invoke|execute|run|trigger|use)\b[^.!?\n]{{0,30}}\b({_TOOLS})\b"
                r"[^.!?\n]{0,40}\b(directly|immediately|silently|without asking"
                r"|for (all|every)|on behalf of)\b",
                0.8,
                "direct tool invocation instruction",
            ),
            (
                rf"\"?(function_?call|tool_?call|tool_use|\"name\")\"?\s*[:=]\s*\"?({_TOOLS})",
                0.85,
                "injected tool-call structure",
            ),
            (
                r"\b(delete|drop|truncate|wipe|erase|destroy)\b[^.!?\n]{0,20}\b(all|every"
                r"|the)\b[^.!?\n]{0,20}\b(students?|users?|courses?|schedules?|tables?"
                r"|database|records|logs|events)\b",
                0.7,
                "destructive operation request",
            ),
        ],
        "fr": [
            (
                r"\b(sans|contourne\w*|saute\w*|evite\w*|pas besoin d'?|ne demande pas)"
                r"\b[^.!?\n]{0,25}\b(approbation|validation|confirmation|verification"
                r"|revue|humain|autorisation|controles?|tool guard|rbac)\b",
                0.9,
                "tentative de contourner l'approbation ou l'autorisation",
            ),
            (
                r"\b(approuve\w*|valide\w*)\b[^.!?\n]{0,20}\b(automatiquement|toi-meme"
                r"|directement|tout seul)\b|\bmarque\w*\b[^.!?\n]{0,25}"
                r"\b(approuvee?|validee?)\b",
                0.85,
                "tentative d'auto-approbation",
            ),
            (
                rf"\b(appelle\w*|execute\w*|lance\w*|declenche\w*|invoque\w*|utilise\w*)\b"
                rf"[^.!?\n]{{0,30}}\b({_TOOLS})\b[^.!?\n]{{0,40}}\b(directement"
                r"|immediatement|sans demander|en silence|discretement|pour tous)\b",
                0.8,
                "instruction d'appel direct d'outil",
            ),
            (
                r"\b(supprime\w*|efface\w*|detrui\w*|vide\w*)\b[^.!?\n]{0,20}\b(tous|toutes"
                r"|les|la|le)\b[^.!?\n]{0,20}\b(etudiants|utilisateurs|cours|tables?"
                r"|base|donnees|logs|journaux|evenements)\b",
                0.7,
                "demande d'operation destructive",
            ),
        ],
    },
    "trust_boundary": {
        "en": [
            (
                r"(?m)^\W{0,4}(system|developer|admin(istrator)?|root|security team"
                r"|google|gemini|openai|anthropic)\s*(message|note|notice|instruction"
                r"|override|prompt)?\W{0,4}:",
                0.8,
                "forged authority header",
            ),
            (
                r"\b(note|message|instructions?|important|attention|warning)\s+(to|for)"
                r"\s+(the\s+)?(ai|assistant|llm|model|chatbot|gemini|agent)\b",
                0.85,
                "instruction addressed to the AI assistant",
            ),
            (
                r"\b(if you are|if you're)\s+(an?\s+)?(ai|assistant|llm|language model"
                r"|chatbot|agent)\b",
                0.75,
                "text targeting automated readers",
            ),
            (
                r"\b(end of (user|the) (input|message|prompt|document)|begin(ning)? (of )?"
                r"(new|system) (instructions?|prompt))\b",
                0.8,
                "forged context delimiter",
            ),
            (
                r"\b(this (message|request|instruction) (is|comes) from|sent by"
                r"|authori[sz]ed by)\s+(the\s+)?(admin(istrator)?|system|security team"
                r"|developers?|it department)\b",
                0.8,
                "claimed authority of the message",
            ),
        ],
        "fr": [
            (
                r"(?m)^\W{0,4}(systeme|developpeur|administrateur|admin|equipe securite)"
                r"\s*(message|note|instruction)?\W{0,4}:",
                0.8,
                "en-tete d'autorite falsifie",
            ),
            (
                r"\b(note|message|instructions?|important|attention|avis|consigne)\s+(a"
                r"|pour|aux?|a l'attention de)\s+(l'|la |le )?(ia|assistant"
                r"|intelligence artificielle|modele|chatbot|agent|llm|gemini)\b",
                0.85,
                "instruction adressee a l'assistant IA",
            ),
            (
                r"\b(si tu es|si vous etes)\s+(une? )?(ia|assistant|intelligence artificielle"
                r"|modele|chatbot|agent)\b",
                0.75,
                "texte ciblant les lecteurs automatises",
            ),
            (
                r"\b(fin (du|de la) (message|requete|document|saisie)|debut (des|de la)"
                r" nouvelles? (instructions?|consignes?))\b",
                0.8,
                "delimiteur de contexte falsifie",
            ),
            (
                r"\b(ce message|cette (demande|instruction|consigne)) (vient|provient|emane)"
                r" (de l'|du |de la )(admin\w*|systeme|direction|equipe securite"
                r"|service informatique)",
                0.8,
                "autorite revendiquee du message",
            ),
        ],
    },
    "signature": {
        "any": [
            (
                r"\b(do anything now|dan mode|developer mode (enabled|on|activated)"
                r"|jailbreak mode|stan prompt|aim mode|grandma exploit)\b",
                0.9,
                "known jailbreak signature",
            ),
            (
                r"<\|?(im_start|im_end|system|endoftext|start_of_turn|end_of_turn)\|?>"
                r"|\[/?inst\]|<</?sys>>|</?(system|instructions?)>",
                0.9,
                "chat-template control token",
            ),
            (
                r"(\.\./|\.\.\\|/etc/passwd|rm\s+-rf|;\s*drop\s+table|\bunion\s+select\b"
                r"|\bos\.system\b|__import__)",
                0.8,
                "code or path injection payload",
            ),
        ],
    },
}

# Separator-free signatures matched only on the letters-only "squeezed" view,
# which exists only when separator or invisible-character obfuscation was seen.
COMPACT: list[tuple[str, str, float, str]] = [
    (
        "instruction_override",
        r"(ignore|disregard|forget|oublie|override)\w{0,20}(instructions?|rules"
        r"|regles|consignes)",
        0.9,
        "obfuscated instruction override",
    ),
    (
        "sensitive_information",
        r"(system|hidden|internal)(prompt|instructions)|promptsysteme",
        0.85,
        "obfuscated system prompt request",
    ),
    (
        "role_manipulation",
        r"(iam|imnow|youarenow|jesuis|tuesmaintenant)(an?|un|le)?(admin|root"
        r"|administrat)",
        0.85,
        "obfuscated role claim",
    ),
    (
        "tool_manipulation",
        r"(without|skip|bypass|sans|contourne)\w{0,6}(approval|approbation|validation)",
        0.85,
        "obfuscated approval bypass",
    ),
    ("signature", r"doanythingnow|developermode|jailbreakmode", 0.9, "obfuscated jailbreak"),
]

# Top-level threat type reported for each detector (compatible with the
# threat types already used by the dashboard).
THREAT_OF = {
    "instruction_override": "PROMPT_INJECTION",
    "role_manipulation": "ROLE_MANIPULATION",
    "jailbreak": "JAILBREAK",
    "sensitive_information": "INFORMATION_LEAKAGE",
    "tool_manipulation": "TOOL_MANIPULATION",
    "trust_boundary": "PROMPT_INJECTION",
    "signature": "PROMPT_INJECTION",
}

# Detectors whose threat becomes INDIRECT_PROMPT_INJECTION when the text comes
# from an untrusted source (document, tool result) instead of the user.
INSTRUCTION_DETECTORS = {
    "instruction_override",
    "role_manipulation",
    "jailbreak",
    "tool_manipulation",
    "trust_boundary",
    "signature",
}
