"""
Phase 15 -- Web Interoperability: real-JS-engine test harness.

The web client (web/client/) is meant to run in a browser, and this
project's test environment has no browser or Node.js available (no
`node`/`npm` on PATH, confirmed during Phase 15's investigation). What
IS available is `quickjs` (a real ES2020 JavaScript engine, embeddable
from Python) -- this module loads the EXACT SAME vendored cryptography
files the browser client imports (web/client/vendor/, real,
unmodified `@noble/post-quantum`/`@noble/ciphers` library code, not a
mock or a reimplementation) into a real quickjs context, so tests can
prove genuine cross-language cryptographic interoperability by
actually executing the JS.

This is NOT a simulation of what the browser would do -- it is the
same JavaScript source the browser loads, run by a different (but
still real, spec-compliant, ES2020) JavaScript engine. What this
harness does NOT prove is anything specific to a browser's own APIs
(WebSocket, actual DOM), since the web client deliberately avoids
depending on any browser-only cryptographic API (no WebCrypto) --
every cryptographic primitive it uses is the same portable JS library
code tested here. See docs/architecture/web_interoperability.md's
"What was and was not dynamically executed" section for the full,
honest scope of what this harness can and cannot stand in for.

Polyfills installed (quickjs has no Web/Node globals at all):
  - crypto.getRandomValues()  -- backed by Python's os.urandom(), the
    same real OS entropy source client-side JS would ultimately use.
  - Object.hasOwn()           -- ES2022; this quickjs build predates
    it. Standard, well-known polyfill, semantically identical.

Variable-naming note: every harness-injected global uses a `__`
prefix specifically to avoid colliding with the vendored libraries'
own (heavily minified, single/double-letter) top-level identifiers --
a real collision was hit and diagnosed during this phase's own
development (see docs/architecture/web_interoperability.md).
"""

import os
import re
from pathlib import Path

import quickjs

WEB_CLIENT_DIR = Path(__file__).resolve().parent.parent / "web" / "client"
WEB_CLIENT_VENDOR_DIR = WEB_CLIENT_DIR / "vendor"

# (module specifier as it appears inside OTHER vendored files' own
# `import{...}from"..."` statements, vendored filename) -- load order
# matters: each entry may only reference specifiers already loaded
# above it. Mirrors web/client/index.html's import map 1:1 -- see
# that file for the browser-side equivalent of this same mapping.
_PQ_MODULES_IN_ORDER = [
    ("/npm/@noble/hashes@2.4.0/utils.js/+esm", "hashes-utils.js"),
    ("/npm/@noble/hashes@2.4.0/sha3.js/+esm", "hashes-sha3.js"),
    ("/npm/@noble/curves@2.4.0/abstract/fft.js/+esm", "curves-fft.js"),
    ("/npm/@noble/curves@2.4.0/utils.js/+esm", "curves-utils.js"),
    ("/npm/@noble/post-quantum@0.7.1/ml-kem.js/+esm", "pq-ml-kem.js"),
    ("/npm/@noble/post-quantum@0.7.1/ml-dsa.js/+esm", "pq-ml-dsa.js"),
]

_CIPHERS_AES_FILE = "ciphers-aes.js"

_POLYFILLS = """
if (!Object.hasOwn) {
  Object.hasOwn = function(obj, prop) {
    return Object.prototype.hasOwnProperty.call(obj, prop);
  };
}
globalThis.crypto = {
  getRandomValues: function(arr) {
    var hex = __pyRandomHex(arr.length);
    for (var i = 0; i < arr.length; i++) {
      arr[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return arr;
  }
};
function __hexToBytes(hex) {
  var arr = new Uint8Array(hex.length / 2);
  for (var i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return arr;
}
function __bytesToHex(u8) {
  var s = "";
  for (var i = 0; i < u8.length; i++) {
    s += ("0" + u8[i].toString(16)).slice(-2);
  }
  return s;
}
globalThis.TextEncoder = function(){};
TextEncoder.prototype.encode = function(s) { return __hexToBytes(__pyUtf8EncodeHex(s)); };
globalThis.TextDecoder = function(){};
TextDecoder.prototype.decode = function(u8) { return __pyUtf8DecodeFromHex(__bytesToHex(u8)); };
globalThis.btoa = function(binaryString) {
  var bytes = new Uint8Array(binaryString.length);
  for (var i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  return __pyBytesToBase64(__bytesToHex(bytes));
};
globalThis.atob = function(b64) {
  var hex = __pyBase64ToHex(b64);
  var bytes = __hexToBytes(hex);
  var s = "";
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
};
"""


def _module_import_statement_stripped_body(text):
    """
    The jsdelivr `+esm` bundles vendored here are real ESM, still
    carrying `import{...}from"/npm/...+esm"` lines for their own
    cross-package dependencies (everything WITHIN one package is
    already flattened by jsdelivr's own bundler -- only cross-package
    boundaries remain as imports). quickjs's Context.eval() has no
    ESM module resolver, so each file is wrapped in an IIFE that
    destructures its dependencies out of a `MODULES` registry (built
    up in the same load order as web/client/index.html's import map)
    instead of using real `import` syntax -- the bundled JS BODY
    itself is never rewritten, only how it receives its two or three
    named imports.
    """

    import re

    text = re.sub(r"^\s*/\*.*?\*/\s*", "", text, flags=re.S)

    named_import_re = re.compile(r'import\{([^}]*)\}from"([^"]*)";?')
    bare_import_re = re.compile(r'import"([^"]*)";?')
    export_re = re.compile(r'export\{([^}]*)\};?\s*(?://.*)?\s*$')

    import_lines = []
    pos = 0
    while True:
        m = named_import_re.match(text, pos)
        if m:
            names, src = m.group(1), m.group(2)
            parts = []
            for item in names.split(","):
                item = item.strip()
                if " as " in item:
                    orig, alias = item.split(" as ")
                else:
                    orig = alias = item
                parts.append(f"{orig.strip()}:{alias.strip()}")
            import_lines.append(f'const {{{",".join(parts)}}} = MODULES[{src!r}];')
            pos = m.end()
            continue
        m2 = bare_import_re.match(text, pos)
        if m2:
            pos = m2.end()
            continue
        break

    body = text[pos:]
    em = export_re.search(body)
    if not em:
        raise ValueError("no export{...} statement found in vendored module")

    export_names = em.group(1)
    body = body[: em.start()]

    ret_parts = []
    for item in export_names.split(","):
        item = item.strip()
        if " as " in item:
            orig, alias = item.split(" as ")
        else:
            orig = alias = item
        ret_parts.append(f"{alias.strip()}:{orig.strip()}")

    return (
        "(function(){\n"
        + "\n".join(import_lines)
        + "\n"
        + body
        + "\nreturn {" + ",".join(ret_parts) + "};\n})()"
    )


def build_web_crypto_context():
    """
    Return a real quickjs.Context with the actual vendored web-client
    cryptography loaded: ``ml_kem768``, ``ml_dsa65`` (both from
    @noble/post-quantum, real ML-KEM-768/ML-DSA-65), and an AES-256-GCM
    factory ``__aesGcm(key, nonce)`` (from @noble/ciphers), plus
    ``__hexToBytes``/``__bytesToHex`` helpers for marshalling values
    across the Python/quickjs boundary (quickjs's Python binding can
    only return strings/numbers/booleans from a wrapped Python
    callable -- see this module's own git history/docs for why hex
    strings, not byte lists, cross that boundary).
    """

    ctx = quickjs.Context()
    ctx.set_memory_limit(200 * 1024 * 1024)

    ctx.add_callable("__pyRandomHex", lambda n: os.urandom(int(n)).hex())
    ctx.add_callable("__pyUtf8EncodeHex", lambda s: s.encode("utf-8").hex())
    ctx.add_callable("__pyUtf8DecodeFromHex", lambda h: bytes.fromhex(h).decode("utf-8"))
    ctx.add_callable("__pyBytesToBase64", lambda h: __import__("base64").b64encode(bytes.fromhex(h)).decode("ascii"))
    ctx.add_callable("__pyBase64ToHex", lambda b64: __import__("base64").b64decode(b64).hex())

    ctx.eval(_POLYFILLS)

    module_source_lines = ["var MODULES = {};"]
    for specifier, filename in _PQ_MODULES_IN_ORDER:
        text = (WEB_CLIENT_VENDOR_DIR / filename).read_text(encoding="utf-8")
        wrapped = _module_import_statement_stripped_body(text)
        module_source_lines.append(f"MODULES[{specifier!r}] = {wrapped};")

    ctx.eval("\n".join(module_source_lines))

    ctx.eval(
        "globalThis.ml_kem768 = "
        "MODULES['/npm/@noble/post-quantum@0.7.1/ml-kem.js/+esm'].ml_kem768;\n"
        "globalThis.ml_dsa65 = "
        "MODULES['/npm/@noble/post-quantum@0.7.1/ml-dsa.js/+esm'].ml_dsa65;"
    )

    # @noble/ciphers's jsdelivr bundle for this exact version has no
    # remaining imports at all (fully self-contained) -- eval'd as a
    # plain top-level script (not wrapped/namespaced) is sufficient;
    # its local top-level `const` binding for the GCM factory is
    # exposed below by name, taken from the file's own trailing
    # `export{...}` line rather than hand-copied.
    aes_text = (WEB_CLIENT_VENDOR_DIR / _CIPHERS_AES_FILE).read_text(encoding="utf-8")
    export_line = aes_text.rsplit("export{", 1)[1]
    gcm_local_name = None
    for item in export_line.rstrip("};\n").split(","):
        item = item.strip()
        if " as gcm" in item:
            gcm_local_name = item.split(" as ")[0].strip()
            break
    if gcm_local_name is None:
        raise ValueError("could not find gcm export in vendored @noble/ciphers aes.js")

    body = aes_text.split("export{", 1)[0]
    ctx.eval(body)
    ctx.eval(f"globalThis.__aesGcm = {gcm_local_name};")

    return ctx


def load_crypto_js_canonical_helpers(ctx):
    """
    Load the REAL, shipped web/client/crypto.js -- not a reimplemented
    copy -- into ``ctx`` (already built by build_web_crypto_context()),
    exposing its canonical-payload/encoding functions
    (canonicalIdentityPayload, canonicalGroupKeyPayload,
    canonicalMessagePayload, utf8, bytesToBase64, base64ToBytes,
    bytesToHex) as plain globals.

    quickjs's Context.eval() has no ESM resolver (see this module's
    own top docstring), so crypto.js's three `import {...} from "...";`
    lines are stripped -- its dependency-touching functions
    (generateKemKeypair, signPayload, encryptForWire, etc., which need
    ml_kem768/ml_dsa65/__aesGcm) are consequently NOT usable through
    this loader. The canonical-payload/encoding functions this
    function exists for need none of those imports -- only
    TextEncoder/DataView/Uint8Array, all polyfilled/native already.
    `export function` / `export async function` is textually reduced
    to `function` / `async function` -- quickjs's plain eval() does
    not understand `export` outside a module -- with no other
    transformation: the function BODIES are byte-identical to the
    real file. A bare re-export line (`export { NAME, ... };` -- Phase
    19.24 added one for EDIT_PAYLOAD_PURPOSE/REACTION_PAYLOAD_PURPOSE)
    is dropped entirely rather than rewritten: it declares nothing new,
    only re-exposes a `const` already defined earlier in the file, so
    the name is already a plain global by the time this line would
    otherwise raise quickjs's "unsupported keyword: export".
    """

    text = (WEB_CLIENT_DIR / "crypto.js").read_text(encoding="utf-8")

    lines = text.split("\n")
    body_lines = [
        line for line in lines
        if not line.startswith("import ")
        and not re.match(r"^export\s*\{[^}]*\}\s*;?\s*$", line)
    ]
    body = "\n".join(body_lines)
    body = body.replace("export async function ", "async function ")
    body = body.replace("export function ", "function ")

    ctx.eval(body)

