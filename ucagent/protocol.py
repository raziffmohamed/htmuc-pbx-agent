"""Wire protocol between the agent (on the PBX) and the UC (agent-api.php).

The agent always initiates; the PBX opens no inbound port for it. Every request carries an HMAC-SHA256 signature over
(method, action, kind, timestamp, nonce, body hash) made with the per-agent secret. Every reply carries a signature over
(request signature, reply body hash), so a forged or replayed reply is rejected by the agent. TLS protects the transport;
the signatures add authenticity and replay protection on top.
"""
import hashlib, hmac, json, os, ssl, time, urllib.error, urllib.parse, urllib.request

PROTO = 'UCAGENT1'
MAX_RESPONSE = 4 * 1024 * 1024
MAX_REQUEST = 4 * 1024 * 1024


class ProtocolError(Exception):
    pass


def body_hash(body):
    return hashlib.sha256(body).hexdigest()


def request_sig(secret, method, action, kind, ts, nonce, bhash):
    msg = '\n'.join([PROTO, method.upper(), action, kind, str(int(ts)), nonce, bhash])
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def response_sig(secret, req_sig, bhash):
    msg = '\n'.join([PROTO + 'R', req_sig, bhash])
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, base_url, agent_id, secret, ca_file=None, timeout=20, allow_http_localhost=False, version=''):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme != 'https' and not (allow_http_localhost and parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')):
            raise ProtocolError('uc_url must be https')
        if not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise ProtocolError('uc_url must be a plain URL')
        self.url = base_url.rstrip('/') + '/agent-api.php'
        self.agent_id, self.secret, self.timeout, self.version = agent_id, secret, timeout, version
        handlers = [_NoRedirect()]
        if parsed.scheme == 'https':
            ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def call(self, method, action, kind='', payload=None, now=None):
        body = b'' if payload is None else json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
        if len(body) > MAX_REQUEST:
            raise ProtocolError('request too large')
        ts = int(now if now is not None else time.time())
        nonce = os.urandom(12).hex()
        sig = request_sig(self.secret, method, action, kind, ts, nonce, body_hash(body))
        query = {'action': action}
        if kind:
            query['kind'] = kind
        req = urllib.request.Request(self.url + '?' + urllib.parse.urlencode(query), data=body if method.upper() == 'POST' else None, method=method.upper())
        req.add_header('X-Agent-Id', self.agent_id)
        req.add_header('X-Agent-Ts', str(ts))
        req.add_header('X-Agent-Nonce', nonce)
        req.add_header('X-Agent-Sig', sig)
        req.add_header('X-Agent-Version', self.version)
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                status, raw, got = resp.status, resp.read(MAX_RESPONSE + 1), resp.headers.get('X-Agent-Resp-Sig', '')
        except urllib.error.HTTPError as e:
            hint = ''
            if e.code == 401:
                hint = ' (not authorised: wrong id/secret, agent disabled, or the clocks differ by more than 2 minutes; server time %s)' % e.headers.get('Date', 'unknown')
            raise ProtocolError('HTTP %d%s' % (e.code, hint))
        except (urllib.error.URLError, OSError) as e:
            raise ProtocolError('connection failed: %s' % getattr(e, 'reason', e))
        if len(raw) > MAX_RESPONSE:
            raise ProtocolError('response too large')
        if status != 200:
            raise ProtocolError('HTTP %d' % status)
        if not hmac.compare_digest(got, response_sig(self.secret, sig, body_hash(raw))):
            raise ProtocolError('reply signature invalid (wrong secret, or not the UC)')
        try:
            data = json.loads(raw.decode())
        except ValueError:
            raise ProtocolError('reply is not JSON')
        if not isinstance(data, dict):
            raise ProtocolError('reply is not an object')
        return data
