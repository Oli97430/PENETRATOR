from gui.engine._core import *

# ---------------------------------------------------------------------------
# Password tools
# ---------------------------------------------------------------------------
def identify_hash(value: str) -> list[str]:
    """Identify possible hash algorithms matching a given hash string."""
    value = value.strip()
    matches = [name for name, pat in HASH_SIGNATURES if pat.match(value)]
    if "MD5" in matches and "NTLM" in matches:
        return ["MD5 / NTLM / LM hash  (32-char hex, context-dependent)"]
    return matches


def crack_hash(value: str, algo: str, wordlist_path: str,
               log: Logger) -> str | None:
    """Attempt to crack a hash by comparing against a wordlist."""
    value = value.strip().lower()
    algo = algo.lower()
    if algo not in SUPPORTED_HASH_ALGOS:
        log(f"[-] Unsupported algorithm: {algo}", "err")
        return None
    path = Path(wordlist_path)
    if not path.is_file():
        log(f"[-] Wordlist not found: {wordlist_path}", "err")
        return None
    log(f"[*] Cracking {algo.upper()} using {path}", "cyan")
    tried = 0
    t0 = time.time()
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if _should_stop():
                log("[!] Stop requested - aborting crack", "warn")
                return None
            word = line.rstrip("\r\n")
            if not word:
                continue
            tried += 1
            digest = hashlib.new(algo, word.encode("utf-8", errors="ignore")).hexdigest()
            if digest == value:
                log(f"[+] Match found after {tried} attempts: {word}", "ok")
                return word
            if tried % 20000 == 0:
                log(f"    ... tried {tried:,} words", "muted")
    log(f"[-] Not found (tried {tried:,} in {time.time()-t0:.2f}s)", "warn")
    return None


def password_strength(pw: str) -> tuple[int, str]:
    """Score a password's strength and return (score, label)."""
    score = 0
    if len(pw) >= 8: score += 1
    if len(pw) >= 12: score += 1
    if re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw): score += 1
    if re.search(r"\d", pw) and re.search(r"[^A-Za-z0-9]", pw): score += 1
    label = {0: "Very weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very strong"}[score]
    return score, label


def generate_password(length: int, upper: bool, digits: bool, symbols: bool) -> str:
    """Generate a cryptographically random password with the given character classes."""
    alphabet = string.ascii_lowercase
    if upper:   alphabet += string.ascii_uppercase
    if digits:  alphabet += string.digits
    if symbols: alphabet += "!@#$%^&*()-_=+[]{};:,.?/"
    return "".join(secrets.choice(alphabet) for _ in range(length))


