"""Test of csrf-protect library.

This test use `PoorWSGI <http://poorhttp.zeropage.cz/poorwsgi.html>`
WSGI middleware. But library could be use with anyone.
"""

from poorwsgi import Application, redirect, SERVER_RETURN, state
from poorwsgi.session import PoorSession

from wsgiref.simple_server import make_server
from inspect import cleandoc

from csrf import random_string, get_token, check_token

app = Application('test')
app.debug = True
secret = random_string(length=32)


def create_referer(req, referer):
    return "%s://%s%s" % (req.scheme, req.hostname, referer)


@app.route('/login')
def login(req):
    # password check is missing !
    cookie = PoorSession(req)
    cookie.data['hash'] = random_string()
    # cookie data are crypted with poorwsgi secret key
    cookie.header(req, req.headers_out)
    redirect(req, '/')


@app.route('/logout')
def logout(req):
    cookie = PoorSession(req)
    cookie.destroy()
    cookie.header(req, req.headers_out)
    redirect(req, '/')


@app.route('/style.css')
def style(req):
    req.content_type = 'text/css'
    return cleandoc("""
        body { max-width: 60em; margin: auto; padding-top: 30px; }
        nav { text-align: right; background: #ccc; line-height: 1.5em; }
    """)


@app.route('/')
@app.route('/not_valid')
def root_uri(req):
    cookie = PoorSession(req)
    if 'hash' in cookie.data:
        referer = create_referer(req, '/')
        token_tmp = get_token(secret, cookie.data['hash'], referer)
        token_ttl = get_token(secret, cookie.data['hash'], referer, 1)
    else:
        token_tmp = token_ttl = ''

    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <title>CSRF Protect test</title>
        <meta http-equiv="content-type" content="text/html; charset=utf-8"/>
        <link rel="stylesheet" href="style.css">
      </head>
      <body>
        <h1>CSRF Protect test</h1>
        <nav>Login state: {login}</nav>
        <p>Base test links for create and destroy login cookie. If login
          cookie is not present (user is not logged), no token is set.</p>
        <ul>
          <li><a href="/">/</a> - Right request referer</li>
          <li><a href="/not_valid">/not_valid</a> - Not valid request referer
            </li>
          <li><a href="/login">/login</a> - Create login cookie</li>
          <li><a href="/logout">/logout</a> - Destroy login cookie</li>
        </ul>

        <p>This is link generate request for CSFR protected uri. If you want it
          from <a href="/not_valid">/not_valid</a> link or without login
          cookie, you got 403 Forbidden Access error page. Otherwise, you got
          right output.</p>
        <ul>
          <li><a href="/protected?token_tmp={token_tmp}">/protected by cookie
            </a></li>
          <li><a href="/protected?token_ttl={token_ttl}">/protected by cookie
            and timeout</a></li>
        </ul>

      </body>
    </html>
    """.format(login=('hash' in cookie.data), uri=req.uri, token_tmp=token_tmp,
               token_ttl=token_ttl)
    return cleandoc(html)


def protected_content(token, referer, timeout):
    return """
    <!DOCTYPE html>
    <html>
      <head>
        <title>CSRF Protect content</title>
        <meta http-equiv="content-type" content="text/html; charset=utf-8"/>
        <link rel="stylesheet" href="style.css">
      </head>
      <body>
        <h1>CSRF Protect content</h1>
        <ul>
          <li>token: {token}</li>
          <li>referer: {referer}</li>
          <li>timeout: {timeout} min.</li>
        </ul>
      </body>
    </html>
    """.format(token=token, referer=referer, timeout=timeout)


@app.route('/protected')
def protected(req):
    cookie = PoorSession(req)
    cookie_hash = cookie.data.get('hash')
    if 'token_tmp' in req.args:
        token = req.args.get('token_tmp')
        referer = req.referer.split('?')[0]
        if not check_token(token, secret, cookie_hash, referer):
            raise SERVER_RETURN(state.HTTP_FORBIDDEN)
        return cleandoc(protected_content(token, referer, None))
    else:
        token = req.args.get('token_ttl')
        referer = req.referer.split('?')[0]
        if not check_token(token, secret, cookie_hash, referer, 1):
            raise SERVER_RETURN(state.HTTP_FORBIDDEN)
        return cleandoc(protected_content(token, referer, 1))


if __name__ == '__main__':
    httpd = make_server('127.0.0.1', 8080, app)
    httpd.serve_forever()
