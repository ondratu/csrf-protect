csrf-protect
============

 * CSRF defintion on `Wikipedia
   <https://en.wikipedia.org/wiki/Cross-site_request_forgery>`_

Very simple library for CSRF protection.

The base mine of this library is secret server key, which is used for
generating token, user hash, which is generating when user is logged in
and reference string, which could be http referer for example.

Each new token is generated on page from which are new requests allowed,
and each method check, if original token is same as which is generated with
same path.

.. code-block:: python

    @app.route('/')
    def root_uri(req):
        # permanent token from user cookie hash (must be protected/crypted)
        token = get_token(secret, cookie.data['hash'], referer)

    @app.route('/')
    def root_uri(req):
        # same example but token expired after 10 - 19 minutes
        token = get_token(secret, cookie.data['hash'], referer, 10)

    @app.route('/protected')
    def protected(req):
        cookie_hash = cookie.data.get('hash')
        token = req.args.get('token')
        referer = req.referer.split('?')[0]

        # permanent token check
        if not check_token(token, secret, cookie_hash, referer):
            raise Exception('token failed')

        # token with time to live information
        if not check_token(token, secret, cookie_hash, referer, 10):
            raise Exception('token failed')
