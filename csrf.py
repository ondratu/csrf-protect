"""Simple library for CSRF protection.

The base mine of this library is secret server key, which is used for
generating token, user hash, which is generating when user is logged in
and reference string, which could be http referer for example.

Each new token is generated on page from which are new requests allowed,
and each method check, if original token is same as which is generated with
same path.

If you are using time-outed tokens, be care that the time of each token is
`double of timeout`, but it start some time in past on timeout aligned time.
It could be good job, to refresh original page with time-outed token in period
less then timeout.

More information about CSRF is on `Wikipedia
<https://en.wikipedia.org/wiki/Cross-site_request_forgery>`_ for example.
"""

from hashlib import sha256
from time import time
from random import randrange, seed

seed()


def random_string(length=24):
    """Return `length` long random string."""
    rv = ''
    for i in range(length):
        rv += chr(randrange(256))
    return rv


def get_token(secret, user_hash, references, timeout=None, expired=0):
    """Create token from secret key, user_hash hash and references.

    If timeout (in minutes) is set, token contains time align to minutes with
    twice of timeout. That is if time of creating is near to computed timeout.
    Argument variable is for internal use, when function is called from
    check_token.
    """
    if timeout is None:
        text = "%s%s%s" % (secret, user_hash, references)
    else:
        shift = 60 * timeout
        if expired == 0:
            now = time()
            now = int(now / shift) * shift     # shift to timeout
            expired = now + 2 * shift
        expired = sha256(str(expired)).hexdigest()
        text = "%s%s%s%s" % (secret, user_hash, references, expired)
    return sha256(text).hexdigest()


def check_token(token, secret, user_hash, references, timeout=None):
    """Check token with generated one.

    If timeout is set, than two token are generated. One for time before
    twice timeout, one before timeout. That is because time is aligned.
    """
    if timeout is None:
        return token == get_token(secret, user_hash, references)
    else:
        now = time()
        shift = 60 * timeout
        now = int(now / shift) * shift      # shift to timeout
        expired = now + 2 * shift
        if token == get_token(secret, user_hash, references, timeout, expired):
            return True

        expired = now + shift
        return token == get_token(secret, user_hash, references, timeout,
                                  expired)
