# Recorded provider calls

Each file is a cassette: gzipped JSON lines, one per call, keyed by the hash of the request (the
method, the host and path, and the request body in canonical JSON). A line keeps the request body,
the status, the response body and the limit headers of the answer, and never a request header, so
no key is ever written here. scripts/check_secrets.py reads inside every cassette.

CI serves these files only (UNSCHED_REPLAY_ONLY=1). agent-record.yml records them with the keys
Ajay added as Actions secrets, when he starts it, and a person commits what it returns.
