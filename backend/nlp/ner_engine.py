import re
import os

ENTITY_BOOSTS = {
    "THREAT_ACTOR": 18,
    "MALWARE":      15,
    "CVE":          12,
    "ATTACK_TECH":   8,
    "RANSOMWARE":   20,
}

KNOWN_THREAT_ACTORS = [
    "APT1","APT10","APT28","APT29","APT32","APT33","APT34","APT38","APT41",
    "Lazarus","Lazarus Group","Cozy Bear","Fancy Bear","Sandworm","Turla",
    "Carbanak","FIN7","FIN8","Lapsus$","REvil","DarkSide","BlackMatter",
    "Conti","LockBit","BlackCat","ALPHV","Cl0p","Vice Society","Hive",
    "TA505","TA542","Kimsuky","Sidewinder","Transparent Tribe","MuddyWater",
    "Charming Kitten","OilRig","APT-C-36","Scattered Spider","UNC2452",
]

KNOWN_MALWARE = [
    "Emotet","TrickBot","Dridex","Ryuk","WannaCry","NotPetya","Mirai",
    "Cobalt Strike","Metasploit","Mimikatz","BloodHound","PowerSploit",
    "AsyncRAT","NjRAT","QuasarRAT","AgentTesla","FormBook","RedLine",
    "Raccoon","Vidar","LokiBot","AZORult","Remcos","DarkComet","Zeus",
    "GootLoader","BazarLoader","IcedID","Qakbot","PlugX","ShadowPad",
    "HermeticWiper","WhisperGate","CaddyWiper","Industroyer","Triton",
    "Stuxnet","BlackEnergy","GandCrab","Sodinokibi","NetWalker","Maze",
    "Ragnar Locker","DoppelPaymer","Dharma","Phobos","STOP","MedusaLocker",
]

MITRE_MAP = {
    "phishing":            ("T1566",     "Phishing"),
    "spear phishing":      ("T1566.001", "Spearphishing Attachment"),
    "brute force":         ("T1110",     "Brute Force"),
    "credential dump":     ("T1003",     "OS Credential Dumping"),
    "mimikatz":            ("T1003.001", "LSASS Memory"),
    "lateral movement":    ("T1021",     "Remote Services"),
    "persistence":         ("T1547",     "Boot/Logon Autostart"),
    "command and control": ("T1071",     "Application Layer Protocol"),
    "c2":                  ("T1071",     "Application Layer Protocol"),
    "data exfiltration":   ("T1041",     "Exfiltration Over C2 Channel"),
    "sql injection":       ("T1190",     "Exploit Public-Facing Application"),
    "ransomware":          ("T1486",     "Data Encrypted for Impact"),
    "cryptomining":        ("T1496",     "Resource Hijacking"),
    "ddos":                ("T1498",     "Network Denial of Service"),
    "port scan":           ("T1046",     "Network Service Discovery"),
    "privilege escalation":("T1068",     "Exploitation for Privilege Escalation"),
    "reverse shell":       ("T1059",     "Command and Scripting Interpreter"),
    "keylogger":           ("T1056",     "Input Capture"),
    "rootkit":             ("T1014",     "Rootkit"),
    "supply chain":        ("T1195",     "Supply Chain Compromise"),
    "watering hole":       ("T1189",     "Drive-by Compromise"),
    "zero day":            ("T1203",     "Exploitation for Client Execution"),
    "tor":                 ("T1090.003", "Multi-hop Proxy"),
    "rdp":                 ("T1021.001", "Remote Desktop Protocol"),
    "ssh":                 ("T1021.004", "SSH"),
    "smb":                 ("T1021.002", "SMB/Windows Admin Shares"),
    "powershell":          ("T1059.001", "PowerShell"),
    "wmi":                 ("T1047",     "Windows Management Instrumentation"),
}


class NEREngine:
    def __init__(self):
        self._model_loaded = False
        self._pipeline     = None

    def try_load_model(self):
        self._model_loaded = False
        print("NER engine ready - regex + knowledge base mode")

    def extract_entities(self, text):
        if not text:
            return self._empty()
        return {
            "threat_actors":    self._extract_threat_actors(text),
            "malware":          self._extract_malware(text),
            "cves":             self._extract_cves(text),
            "mitre_techniques": self._extract_mitre(text),
            "attack_types":     self._extract_attack_types(text),
        }

    def calculate_boost(self, entities):
        boost   = 0
        reasons = []
        if entities.get("threat_actors"):
            b = min(len(entities["threat_actors"]) * ENTITY_BOOSTS["THREAT_ACTOR"], 25)
            boost += b
            reasons.append("Known threat actor: " + ", ".join(entities["threat_actors"][:2]))
        if entities.get("malware"):
            b = min(len(entities["malware"]) * ENTITY_BOOSTS["MALWARE"], 20)
            boost += b
            reasons.append("Malware family: " + ", ".join(entities["malware"][:2]))
        if entities.get("cves"):
            b = min(len(entities["cves"]) * ENTITY_BOOSTS["CVE"], 20)
            boost += b
            reasons.append("CVE found: " + ", ".join(entities["cves"][:3]))
        if entities.get("mitre_techniques"):
            b = min(len(entities["mitre_techniques"]) * ENTITY_BOOSTS["ATTACK_TECH"], 15)
            boost += b
            ids = [t[0] for t in entities["mitre_techniques"][:2]]
            reasons.append("MITRE ATT&CK: " + ", ".join(ids))
        return min(boost, 30), reasons

    def _extract_threat_actors(self, text):
        found = []
        text_lower = text.lower()
        for actor in KNOWN_THREAT_ACTORS:
            if actor.lower() in text_lower:
                found.append(actor)
        return list(set(found))

    def _extract_malware(self, text):
        found = []
        text_lower = text.lower()
        for malware in KNOWN_MALWARE:
            if malware.lower() in text_lower:
                found.append(malware)
        return list(set(found))

    def _extract_cves(self, text):
        pattern = r"CVE-\d{4}-\d{4,7}"
        return list(set(re.findall(pattern, text, re.IGNORECASE)))

    def _extract_mitre(self, text):
        found = []
        text_lower = text.lower()
        for keyword, (tid, tname) in MITRE_MAP.items():
            if keyword in text_lower:
                found.append((tid, tname))
        direct = re.findall(r"T\d{4}(?:\.\d{3})?", text)
        for code in direct:
            if not any(t[0] == code for t in found):
                found.append((code, "ATT&CK Technique"))
        return list({t[0]: t for t in found}.values())[:10]

    def _extract_attack_types(self, text):
        keywords = [
            "ransomware","backdoor","trojan","botnet","rootkit","keylogger",
            "worm","virus","spyware","cryptominer","stealer","downloader",
            "dropper","loader","rat","apt","zero-day","exploit","injection",
        ]
        text_lower = text.lower()
        return [k for k in keywords if k in text_lower]

    def _empty(self):
        return {
            "threat_actors":[], "malware":[], "cves":[],
            "mitre_techniques":[], "attack_types":[],
        }


ner = NEREngine()
