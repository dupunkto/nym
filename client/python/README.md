# Nym

Identity provider and authentication layer.

Client library for protecting Flask applications with a [Nym](https://git.dupunkto.org/~dupunkto/nym) endpoint.

## Usage

```python
from flask import Flask
from nym import Nym, require_auth

app = Flask(__name__)
app.secret_key = "..."  # required by Flask for sessions

nym = Nym()
nym.init_app(app, endpoint="https://nym.example.com", scopes=["profile"])

@app.route("/protected")
@require_auth
def protected():
    ...
```

`Nym.init_app` also supports the Flask application-factory pattern:

```python
nym = Nym()

def create_app():
    app = Flask(__name__)
    app.secret_key = "..."
    nym.init_app(app, endpoint="https://nym.example.com")
    return app
```

Every request has `flask.g.current_user` and `flask.g.authenticated` populated from the
session, whether or not the view is behind `@require_auth`.
