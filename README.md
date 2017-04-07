# api documentation for  [oauth2orize (v1.8.0)](https://github.com/jaredhanson/oauth2orize#readme)  [![npm package](https://img.shields.io/npm/v/npmdoc-oauth2orize.svg?style=flat-square)](https://www.npmjs.org/package/npmdoc-oauth2orize) [![travis-ci.org build-status](https://api.travis-ci.org/npmdoc/node-npmdoc-oauth2orize.svg)](https://travis-ci.org/npmdoc/node-npmdoc-oauth2orize)
#### OAuth 2.0 authorization server toolkit for Node.js.

[![NPM](https://nodei.co/npm/oauth2orize.png?downloads=true)](https://www.npmjs.com/package/oauth2orize)

[![apidoc](https://npmdoc.github.io/node-npmdoc-oauth2orize/build/screenCapture.buildNpmdoc.browser._2Fhome_2Ftravis_2Fbuild_2Fnpmdoc_2Fnode-npmdoc-oauth2orize_2Ftmp_2Fbuild_2Fapidoc.html.png)](https://npmdoc.github.io/node-npmdoc-oauth2orize/build/apidoc.html)

![npmPackageListing](https://npmdoc.github.io/node-npmdoc-oauth2orize/build/screenCapture.npmPackageListing.svg)

![npmPackageDependencyTree](https://npmdoc.github.io/node-npmdoc-oauth2orize/build/screenCapture.npmPackageDependencyTree.svg)



# package.json

```json

{
    "author": {
        "name": "Jared Hanson",
        "email": "jaredhanson@gmail.com",
        "url": "http://www.jaredhanson.net/"
    },
    "bugs": {
        "url": "http://github.com/jaredhanson/oauth2orize/issues"
    },
    "dependencies": {
        "debug": "2.x.x",
        "uid2": "0.0.x",
        "utils-merge": "1.x.x"
    },
    "description": "OAuth 2.0 authorization server toolkit for Node.js.",
    "devDependencies": {
        "chai": "2.x.x",
        "chai-connect-middleware": "0.3.x",
        "chai-oauth2orize-grant": "0.3.x",
        "make-node": "0.3.x",
        "mocha": "2.x.x"
    },
    "directories": {},
    "dist": {
        "shasum": "f2ddc0115d635d0480746249c00f0ea1a9c51ba8",
        "tarball": "https://registry.npmjs.org/oauth2orize/-/oauth2orize-1.8.0.tgz"
    },
    "engines": {
        "node": ">= 0.4.0"
    },
    "gitHead": "58cbc13f0097294cf245e9ed85c29e55e979cac5",
    "homepage": "https://github.com/jaredhanson/oauth2orize#readme",
    "keywords": [
        "oauth",
        "oauth2",
        "auth",
        "authz",
        "authorization",
        "connect",
        "express",
        "passport",
        "middleware"
    ],
    "license": "MIT",
    "licenses": [
        {
            "type": "MIT",
            "url": "http://opensource.org/licenses/MIT"
        }
    ],
    "main": "./lib",
    "maintainers": [
        {
            "name": "jaredhanson",
            "email": "jaredhanson@gmail.com"
        }
    ],
    "name": "oauth2orize",
    "optionalDependencies": {},
    "readme": "ERROR: No README data found!",
    "repository": {
        "type": "git",
        "url": "git://github.com/jaredhanson/oauth2orize.git"
    },
    "scripts": {
        "test": "mocha --reporter spec --require test/bootstrap/node test/*.test.js test/**/*.test.js"
    },
    "version": "1.8.0"
}
```



# <a name="apidoc.tableOfContents"></a>[table of contents](#apidoc.tableOfContents)

#### [module oauth2orize](#apidoc.module.oauth2orize)
1.  [function <span class="apidocSignatureSpan">oauth2orize.</span>AuthorizationError (message, code, uri, status)](#apidoc.element.oauth2orize.AuthorizationError)
1.  [function <span class="apidocSignatureSpan">oauth2orize.</span>OAuth2Error (message, code, uri, status)](#apidoc.element.oauth2orize.OAuth2Error)
1.  [function <span class="apidocSignatureSpan">oauth2orize.</span>TokenError (message, code, uri, status)](#apidoc.element.oauth2orize.TokenError)
1.  [function <span class="apidocSignatureSpan">oauth2orize.</span>createServer (options)](#apidoc.element.oauth2orize.createServer)
1.  [function <span class="apidocSignatureSpan">oauth2orize.</span>errorHandler (options)](#apidoc.element.oauth2orize.errorHandler)
1.  [function <span class="apidocSignatureSpan">oauth2orize.</span>server (options)](#apidoc.element.oauth2orize.server)
1.  [function <span class="apidocSignatureSpan">oauth2orize.</span>unorderedlist (items)](#apidoc.element.oauth2orize.unorderedlist)
1.  object <span class="apidocSignatureSpan">oauth2orize.</span>exchange
1.  object <span class="apidocSignatureSpan">oauth2orize.</span>grant
1.  object <span class="apidocSignatureSpan">oauth2orize.</span>server.prototype
1.  object <span class="apidocSignatureSpan">oauth2orize.</span>unorderedlist.prototype
1.  object <span class="apidocSignatureSpan">oauth2orize.</span>utils

#### [module oauth2orize.exchange](#apidoc.module.oauth2orize.exchange)
1.  [function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>authorizationCode (options, issue)](#apidoc.element.oauth2orize.exchange.authorizationCode)
1.  [function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>clientCredentials (options, issue)](#apidoc.element.oauth2orize.exchange.clientCredentials)
1.  [function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>code (options, issue)](#apidoc.element.oauth2orize.exchange.code)
1.  [function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>password (options, issue)](#apidoc.element.oauth2orize.exchange.password)
1.  [function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>refreshToken (options, issue)](#apidoc.element.oauth2orize.exchange.refreshToken)

#### [module oauth2orize.grant](#apidoc.module.oauth2orize.grant)
1.  [function <span class="apidocSignatureSpan">oauth2orize.grant.</span>authorizationCode (options, issue)](#apidoc.element.oauth2orize.grant.authorizationCode)
1.  [function <span class="apidocSignatureSpan">oauth2orize.grant.</span>code (options, issue)](#apidoc.element.oauth2orize.grant.code)
1.  [function <span class="apidocSignatureSpan">oauth2orize.grant.</span>implicit (options, issue)](#apidoc.element.oauth2orize.grant.implicit)
1.  [function <span class="apidocSignatureSpan">oauth2orize.grant.</span>token (options, issue)](#apidoc.element.oauth2orize.grant.token)

#### [module oauth2orize.server](#apidoc.module.oauth2orize.server)
1.  [function <span class="apidocSignatureSpan">oauth2orize.</span>server (options)](#apidoc.element.oauth2orize.server.server)

#### [module oauth2orize.server.prototype](#apidoc.module.oauth2orize.server.prototype)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>_exchange (type, req, res, cb)](#apidoc.element.oauth2orize.server.prototype._exchange)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>_parse (type, req, cb)](#apidoc.element.oauth2orize.server.prototype._parse)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>_respond (txn, res, complete, cb)](#apidoc.element.oauth2orize.server.prototype._respond)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>_respondError (err, txn, res, cb)](#apidoc.element.oauth2orize.server.prototype._respondError)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorization (options, validate, immediate)](#apidoc.element.oauth2orize.server.prototype.authorization)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorizationError (options)](#apidoc.element.oauth2orize.server.prototype.authorizationError)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorizationErrorHandler (options)](#apidoc.element.oauth2orize.server.prototype.authorizationErrorHandler)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorize (options, validate, immediate)](#apidoc.element.oauth2orize.server.prototype.authorize)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorizeError (options)](#apidoc.element.oauth2orize.server.prototype.authorizeError)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>decision (options, parse)](#apidoc.element.oauth2orize.server.prototype.decision)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>deserializeClient (fn, done)](#apidoc.element.oauth2orize.server.prototype.deserializeClient)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>errorHandler (options)](#apidoc.element.oauth2orize.server.prototype.errorHandler)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>exchange (type, fn)](#apidoc.element.oauth2orize.server.prototype.exchange)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>grant (type, phase, fn)](#apidoc.element.oauth2orize.server.prototype.grant)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>resume (options, immediate)](#apidoc.element.oauth2orize.server.prototype.resume)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>serializeClient (fn, done)](#apidoc.element.oauth2orize.server.prototype.serializeClient)
1.  [function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>token (options)](#apidoc.element.oauth2orize.server.prototype.token)

#### [module oauth2orize.unorderedlist](#apidoc.module.oauth2orize.unorderedlist)
1.  [function <span class="apidocSignatureSpan">oauth2orize.</span>unorderedlist (items)](#apidoc.element.oauth2orize.unorderedlist.unorderedlist)

#### [module oauth2orize.unorderedlist.prototype](#apidoc.module.oauth2orize.unorderedlist.prototype)
1.  [function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>_length ()](#apidoc.element.oauth2orize.unorderedlist.prototype._length)
1.  [function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>contains (val)](#apidoc.element.oauth2orize.unorderedlist.prototype.contains)
1.  [function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>containsAny (arr)](#apidoc.element.oauth2orize.unorderedlist.prototype.containsAny)
1.  [function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>equalTo (other)](#apidoc.element.oauth2orize.unorderedlist.prototype.equalTo)
1.  [function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>toString ()](#apidoc.element.oauth2orize.unorderedlist.prototype.toString)

#### [module oauth2orize.utils](#apidoc.module.oauth2orize.utils)
1.  [function <span class="apidocSignatureSpan">oauth2orize.utils.</span>merge (a, b)](#apidoc.element.oauth2orize.utils.merge)
1.  [function <span class="apidocSignatureSpan">oauth2orize.utils.</span>uid (length, cb)](#apidoc.element.oauth2orize.utils.uid)



# <a name="apidoc.module.oauth2orize"></a>[module oauth2orize](#apidoc.module.oauth2orize)

#### <a name="apidoc.element.oauth2orize.AuthorizationError"></a>[function <span class="apidocSignatureSpan">oauth2orize.</span>AuthorizationError (message, code, uri, status)](#apidoc.element.oauth2orize.AuthorizationError)
- description and source-code
```javascript
function AuthorizationError(message, code, uri, status) {
  if (!status) {
    switch (code) {
      case 'invalid_request': status = 400; break;
      case 'unauthorized_client': status = 403; break;
      case 'access_denied': status = 403; break;
      case 'unsupported_response_type': status = 501; break;
      case 'invalid_scope': status = 400; break;
      case 'temporarily_unavailable': status = 503; break;
    }
  }

  OAuth2Error.call(this, message, code, uri, status);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'AuthorizationError';
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.OAuth2Error"></a>[function <span class="apidocSignatureSpan">oauth2orize.</span>OAuth2Error (message, code, uri, status)](#apidoc.element.oauth2orize.OAuth2Error)
- description and source-code
```javascript
function OAuth2Error(message, code, uri, status) {
  Error.call(this);
  this.message = message;
  this.code = code || 'server_error';
  this.uri = uri;
  this.status = status || 500;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.TokenError"></a>[function <span class="apidocSignatureSpan">oauth2orize.</span>TokenError (message, code, uri, status)](#apidoc.element.oauth2orize.TokenError)
- description and source-code
```javascript
function TokenError(message, code, uri, status) {
  if (!status) {
    switch (code) {
      case 'invalid_request': status = 400; break;
      case 'invalid_client': status = 401; break;
      case 'invalid_grant': status = 403; break;
      case 'unauthorized_client': status = 403; break;
      case 'unsupported_grant_type': status = 501; break;
      case 'invalid_scope': status = 400; break;
    }
  }

  OAuth2Error.call(this, message, code, uri, status);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'TokenError';
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.createServer"></a>[function <span class="apidocSignatureSpan">oauth2orize.</span>createServer (options)](#apidoc.element.oauth2orize.createServer)
- description and source-code
```javascript
function createServer(options) {
  var server = new Server(options);
  return server;
}
```
- example usage
```shell
...

#### Create an OAuth Server

Call 'createServer()' to create a new OAuth 2.0 server.  This instance exposes
middleware that will be mounted in routes, as well as configuration options.

'''javascript
var server = oauth2orize.createServer();
'''

#### Register Grants

A client must obtain permission from a user before it is issued an access token.
This permission is known as a grant, the most common type of which is an
authorization code.
...
```

#### <a name="apidoc.element.oauth2orize.errorHandler"></a>[function <span class="apidocSignatureSpan">oauth2orize.</span>errorHandler (options)](#apidoc.element.oauth2orize.errorHandler)
- description and source-code
```javascript
errorHandler = function (options) {
  options = options || {};

  var mode = options.mode || 'direct'
    , fragment = options.fragment || ['token']
    , modes = options.modes || {};

  if (!modes.query) {
    modes.query = require('../response/query');
  }
  if (!modes.fragment) {
    modes.fragment = require('../response/fragment');
  }

  return function errorHandler(err, req, res, next) {
    if (mode == 'direct') {
      if (err.status) { res.statusCode = err.status; }
      if (!res.statusCode || res.statusCode < 400) { res.statusCode = 500; }

      if (res.statusCode == 401) {
        // TODO: set WWW-Authenticate header
      }

      var e = {};
      e.error = err.code || 'server_error';
      if (err.message) { e.error_description = err.message; }
      if (err.uri) { e.error_uri = err.uri; }

      res.setHeader('Content-Type', 'application/json');
      return res.end(JSON.stringify(e));
    } else if (mode == 'indirect') {
      // If the redirectURI for this OAuth 2.0 transaction is invalid, the user
      // agent will not be redirected and the client will not be informed.  'next'
      // immediately into the application's error handler, so a message can be
      // displayed to the user.
      if (!req.oauth2 || !req.oauth2.redirectURI) { return next(err); }

      var enc = 'query';
      if (req.oauth2.req) {
        var type = new UnorderedList(req.oauth2.req.type);
        // In accordance with [OAuth 2.0 Multiple Response Type Encoding
        // Practices - draft 08](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html),
        // if the response type contains any value that requires fragment
        // encoding, the response will be fragment encoded.
        if (type.containsAny(fragment)) { enc = 'fragment'; }
        if (req.oauth2.req.responseMode) {
          // Encode the response using the requested mode, if specified.
          enc = req.oauth2.req.responseMode;
        }
      }

      var respond = modes[enc]
        , params = {};

      if (!respond) { return next(err); }

      params.error = err.code || 'server_error';
      if (err.message) { params.error_description = err.message; }
      if (err.uri) { params.error_uri = err.uri; }
      if (req.oauth2.req && req.oauth2.req.state) { params.state = req.oauth2.req.state; }
      return respond(req.oauth2, res, params);
    } else {
      return next(err);
    }
  };
}
```
- example usage
```shell
...
Once a user has approved access, the authorization grant can be exchanged by the
client for an access token.

'''javascript
app.post('/token',
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  server.token(),
  server.errorHandler());
'''

[Passport](http://passportjs.org/) strategies are used to authenticate the
client, in this case using either an HTTP Basic authentication header (as
provided by [passport-http](https://github.com/jaredhanson/passport-http)) or
client credentials in the request body (as provided by
[passport-oauth2-client-password](https://github.com/jaredhanson/passport-oauth2-client-password)).
...
```

#### <a name="apidoc.element.oauth2orize.server"></a>[function <span class="apidocSignatureSpan">oauth2orize.</span>server (options)](#apidoc.element.oauth2orize.server)
- description and source-code
```javascript
function Server(options) {
  options = options || {};
  this._reqParsers = [];
  this._resHandlers = [];
  this._errHandlers = [];
  this._exchanges = [];

  this._serializers = [];
  this._deserializers = [];
  this._txnStore = options.store || new SessionStore();
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.unorderedlist"></a>[function <span class="apidocSignatureSpan">oauth2orize.</span>unorderedlist (items)](#apidoc.element.oauth2orize.unorderedlist)
- description and source-code
```javascript
function UnorderedList(items) {
  if (typeof items == 'string') {
    items = items.split(' ');
  }
  this._items = items || [];
  this.__defineGetter__('length', this._length);
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth2orize.exchange"></a>[module oauth2orize.exchange](#apidoc.module.oauth2orize.exchange)

#### <a name="apidoc.element.oauth2orize.exchange.authorizationCode"></a>[function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>authorizationCode (options, issue)](#apidoc.element.oauth2orize.exchange.authorizationCode)
- description and source-code
```javascript
authorizationCode = function (options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.authorizationCode exchange requires an issue callback'); }

  var userProperty = options.userProperty || 'user';

  return function authorization_code(req, res, next) {
    if (!req.body) { return next(new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?')); }

    // The 'user' property of 'req' holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    var client = req[userProperty]
      , code = req.body.code
      , redirectURI = req.body.redirect_uri;

    if (!code) { return next(new TokenError('Missing required parameter: code', 'invalid_request')); }

    function issued(err, accessToken, refreshToken, params) {
      if (err) { return next(err); }
      if (!accessToken) { return next(new TokenError('Invalid authorization code', 'invalid_grant')); }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }

      var tok = {};
      tok.access_token = accessToken;
      if (refreshToken) { tok.refresh_token = refreshToken; }
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';

      var json = JSON.stringify(tok);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(json);
    }

    try {
      var arity = issue.length;
      if (arity == 6) {
        issue(client, code, redirectURI, req.body, req.authInfo, issued);
      } else if (arity == 5) {
        issue(client, code, redirectURI, req.body, issued);
      } else { // arity == 4
        issue(client, code, redirectURI, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  };
}
```
- example usage
```shell
...
* OAuth 2.0 defines an authorization framework, in which authorization grants
* can be of a variety of types.  Exchanging of these types for access tokens is
* implemented by exchange middleware, and the server registers the middleware
* it wishes to support.
*
* Examples:
*
*     server.exchange(oauth2orize.exchange.authorizationCode(function() {
*       ...
*     }));
*
* @param {String|Function} type
* @param {Function} fn
* @return {Server} for chaining
* @api public
...
```

#### <a name="apidoc.element.oauth2orize.exchange.clientCredentials"></a>[function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>clientCredentials (options, issue)](#apidoc.element.oauth2orize.exchange.clientCredentials)
- description and source-code
```javascript
clientCredentials = function (options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.clientCredentials exchange requires an issue callback'); }

  var userProperty = options.userProperty || 'user';

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }

  return function client_credentials(req, res, next) {
    if (!req.body) { return next(new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?')); }

    // The 'user' property of 'req' holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    var client = req[userProperty]
      , scope = req.body.scope;

    if (scope) {
      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }
      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }

    function issued(err, accessToken, refreshToken, params) {
      if (err) { return next(err); }
      if (!accessToken) { return next(new TokenError('Invalid client credentials', 'invalid_grant')); }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }

      var tok = {};
      tok.access_token = accessToken;
      if (refreshToken) { tok.refresh_token = refreshToken; }
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';

      var json = JSON.stringify(tok);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(json);
    }

    try {
      var arity = issue.length;
      if (arity == 5) {
        issue(client, scope, req.body, req.authInfo, issued);
      } else if (arity == 4) {
        issue(client, scope, req.body, issued);
      } else if (arity == 3) {
        issue(client, scope, issued);
      } else { // arity == 2
        issue(client, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  };
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.exchange.code"></a>[function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>code (options, issue)](#apidoc.element.oauth2orize.exchange.code)
- description and source-code
```javascript
code = function (options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.authorizationCode exchange requires an issue callback'); }

  var userProperty = options.userProperty || 'user';

  return function authorization_code(req, res, next) {
    if (!req.body) { return next(new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?')); }

    // The 'user' property of 'req' holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    var client = req[userProperty]
      , code = req.body.code
      , redirectURI = req.body.redirect_uri;

    if (!code) { return next(new TokenError('Missing required parameter: code', 'invalid_request')); }

    function issued(err, accessToken, refreshToken, params) {
      if (err) { return next(err); }
      if (!accessToken) { return next(new TokenError('Invalid authorization code', 'invalid_grant')); }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }

      var tok = {};
      tok.access_token = accessToken;
      if (refreshToken) { tok.refresh_token = refreshToken; }
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';

      var json = JSON.stringify(tok);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(json);
    }

    try {
      var arity = issue.length;
      if (arity == 6) {
        issue(client, code, redirectURI, req.body, req.authInfo, issued);
      } else if (arity == 5) {
        issue(client, code, redirectURI, req.body, issued);
      } else { // arity == 4
        issue(client, code, redirectURI, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  };
}
```
- example usage
```shell
...

#### Register Grants

A client must obtain permission from a user before it is issued an access token.
This permission is known as a grant, the most common type of which is an
authorization code.
'''javascript
server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
var code = utils.uid(16);

var ac = new AuthorizationCode(code, client.id, redirectURI, user.id, ares.scope);
ac.save(function(err) {
  if (err) { return done(err); }
  return done(null, code);
});
...
```

#### <a name="apidoc.element.oauth2orize.exchange.password"></a>[function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>password (options, issue)](#apidoc.element.oauth2orize.exchange.password)
- description and source-code
```javascript
password = function (options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.password exchange requires an issue callback'); }

  var userProperty = options.userProperty || 'user';

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }

  return function password(req, res, next) {
    if (!req.body) { return next(new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?')); }

    // The 'user' property of 'req' holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    var client = req[userProperty]
      , username = req.body.username
      , passwd = req.body.password
      , scope = req.body.scope;

    if (!username) { return next(new TokenError('Missing required parameter: username', 'invalid_request')); }
    if (!passwd) { return next(new TokenError('Missing required parameter: password', 'invalid_request')); }

    if (scope) {
      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }
      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }

    function issued(err, accessToken, refreshToken, params) {
      if (err) { return next(err); }
      if (!accessToken) { return next(new TokenError('Invalid resource owner credentials', 'invalid_grant')); }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }

      var tok = {};
      tok.access_token = accessToken;
      if (refreshToken) { tok.refresh_token = refreshToken; }
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';

      var json = JSON.stringify(tok);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(json);
    }

    try {
      var arity = issue.length;
      if (arity == 7) {
        issue(client, username, passwd, scope, req.body, req.authInfo, issued);
      } else if (arity == 6) {
        issue(client, username, passwd, scope, req.body, issued);
      } else if (arity == 5) {
        issue(client, username, passwd, scope, issued);
      } else { // arity == 4
        issue(client, username, passwd, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  };
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.exchange.refreshToken"></a>[function <span class="apidocSignatureSpan">oauth2orize.exchange.</span>refreshToken (options, issue)](#apidoc.element.oauth2orize.exchange.refreshToken)
- description and source-code
```javascript
refreshToken = function (options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.refreshToken exchange requires an issue callback'); }

  var userProperty = options.userProperty || 'user';

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }

  return function refresh_token(req, res, next) {
    if (!req.body) { return next(new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?')); }

    // The 'user' property of 'req' holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    var client = req[userProperty]
      , refreshToken = req.body.refresh_token
      , scope = req.body.scope;

    if (!refreshToken) { return next(new TokenError('Missing required parameter: refresh_token', 'invalid_request')); }

    if (scope) {
      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }
      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }

    function issued(err, accessToken, refreshToken, params) {
      if (err) { return next(err); }
      if (!accessToken) { return next(new TokenError('Invalid refresh token', 'invalid_grant')); }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }

      var tok = {};
      tok.access_token = accessToken;
      if (refreshToken) { tok.refresh_token = refreshToken; }
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';

      var json = JSON.stringify(tok);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(json);
    }

    try {
      var arity = issue.length;
      if (arity == 6) {
        issue(client, refreshToken, scope, req.body, req.authInfo, issued);
      } else if (arity == 5) {
        issue(client, refreshToken, scope, req.body, issued);
      } else if (arity == 4) {
        issue(client, refreshToken, scope, issued);
      } else { // arity == 3
        issue(client, refreshToken, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  };
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth2orize.grant"></a>[module oauth2orize.grant](#apidoc.module.oauth2orize.grant)

#### <a name="apidoc.element.oauth2orize.grant.authorizationCode"></a>[function <span class="apidocSignatureSpan">oauth2orize.grant.</span>authorizationCode (options, issue)](#apidoc.element.oauth2orize.grant.authorizationCode)
- description and source-code
```javascript
function code(options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.code grant requires an issue callback'); }

  var modes = options.modes || {};
  if (!modes.query) {
    modes.query = require('../response/query');
  }

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }


<span class="apidocCodeCommentSpan">  /* Parse requests that request 'code' as 'response_type'.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
</span>  function request(req) {
    var clientID = req.query.client_id
      , redirectURI = req.query.redirect_uri
      , scope = req.query.scope
      , state = req.query.state;

    if (!clientID) { throw new AuthorizationError('Missing required parameter: client_id', 'invalid_request'); }
    if (typeof clientID !== 'string') { throw new AuthorizationError('Invalid parameter: client_id must be a string', 'invalid_request
'); }

    if (scope) {
      if (typeof scope !== 'string') {
        throw new AuthorizationError('Invalid parameter: scope must be a string', 'invalid_request');
      }

      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }

      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }

    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state
    };
  }

  /* Sends responses to transactions that request 'code' as 'response_type'.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */
  function response(txn, res, complete, next) {
    var mode = 'query'
      , respond;
    if (txn.req && txn.req.responseMode) {
      mode = txn.req.responseMode;
    }
    respond = modes[mode];

    if (!respond) {
      // http://lists.openid.net/pipermail/openid-specs-ab/Week-of-Mon-20140317/004680.html
      return next(new AuthorizationError('Unsupported response mode: ' + mode, 'unsupported_response_mode', null, 501));
    }
    if (respond && respond.validate) {
      try {
        respond.validate(txn);
      } catch(ex) {
        return next(ex);
      }
    }

    if (!txn.res.allow) {
      var params = { error: 'access_denied' };
      if (txn.req && txn.req.state) { params.state = txn.req.state; }
      return respond(txn, res, params);
    }

    function issued(err, code) {
      if (err) { return next(err); }
      if (!code) { return next(new AuthorizationError('Request denied by authorization server', 'access_denied')); }

      var params = { code: code };
      if (txn.req && txn.req.state) { params.state = txn.req.state; }
      complete(function(err) {
        if (err) { return next(err); }
        return respond(txn, res, params);
      });
    }

    // NOTE: The 'redirect_uri', if present in the client's authorization
    //       request, must also be present in the subsequent request to exchange
    //       the authorization code for an access token.  Acting as a verifier,
    //       the two values must be equal and serve to protect against certain
    //       types of attacks.  More information can be found here:
    //
    //       http://hueniverse.com/2011/06/oauth-2-0-redirection-uri-validation/

    try {
      var arity = issue.length;
      if (arity == 7) {
        issue(txn.client, txn ...
```
- example usage
```shell
...
* OAuth 2.0 defines an authorization framework, in which authorization grants
* can be of a variety of types.  Exchanging of these types for access tokens is
* implemented by exchange middleware, and the server registers the middleware
* it wishes to support.
*
* Examples:
*
*     server.exchange(oauth2orize.exchange.authorizationCode(function() {
*       ...
*     }));
*
* @param {String|Function} type
* @param {Function} fn
* @return {Server} for chaining
* @api public
...
```

#### <a name="apidoc.element.oauth2orize.grant.code"></a>[function <span class="apidocSignatureSpan">oauth2orize.grant.</span>code (options, issue)](#apidoc.element.oauth2orize.grant.code)
- description and source-code
```javascript
function code(options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.code grant requires an issue callback'); }

  var modes = options.modes || {};
  if (!modes.query) {
    modes.query = require('../response/query');
  }

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }


<span class="apidocCodeCommentSpan">  /* Parse requests that request 'code' as 'response_type'.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
</span>  function request(req) {
    var clientID = req.query.client_id
      , redirectURI = req.query.redirect_uri
      , scope = req.query.scope
      , state = req.query.state;

    if (!clientID) { throw new AuthorizationError('Missing required parameter: client_id', 'invalid_request'); }
    if (typeof clientID !== 'string') { throw new AuthorizationError('Invalid parameter: client_id must be a string', 'invalid_request
'); }

    if (scope) {
      if (typeof scope !== 'string') {
        throw new AuthorizationError('Invalid parameter: scope must be a string', 'invalid_request');
      }

      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }

      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }

    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state
    };
  }

  /* Sends responses to transactions that request 'code' as 'response_type'.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */
  function response(txn, res, complete, next) {
    var mode = 'query'
      , respond;
    if (txn.req && txn.req.responseMode) {
      mode = txn.req.responseMode;
    }
    respond = modes[mode];

    if (!respond) {
      // http://lists.openid.net/pipermail/openid-specs-ab/Week-of-Mon-20140317/004680.html
      return next(new AuthorizationError('Unsupported response mode: ' + mode, 'unsupported_response_mode', null, 501));
    }
    if (respond && respond.validate) {
      try {
        respond.validate(txn);
      } catch(ex) {
        return next(ex);
      }
    }

    if (!txn.res.allow) {
      var params = { error: 'access_denied' };
      if (txn.req && txn.req.state) { params.state = txn.req.state; }
      return respond(txn, res, params);
    }

    function issued(err, code) {
      if (err) { return next(err); }
      if (!code) { return next(new AuthorizationError('Request denied by authorization server', 'access_denied')); }

      var params = { code: code };
      if (txn.req && txn.req.state) { params.state = txn.req.state; }
      complete(function(err) {
        if (err) { return next(err); }
        return respond(txn, res, params);
      });
    }

    // NOTE: The 'redirect_uri', if present in the client's authorization
    //       request, must also be present in the subsequent request to exchange
    //       the authorization code for an access token.  Acting as a verifier,
    //       the two values must be equal and serve to protect against certain
    //       types of attacks.  More information can be found here:
    //
    //       http://hueniverse.com/2011/06/oauth-2-0-redirection-uri-validation/

    try {
      var arity = issue.length;
      if (arity == 7) {
        issue(txn.client, txn ...
```
- example usage
```shell
...

#### Register Grants

A client must obtain permission from a user before it is issued an access token.
This permission is known as a grant, the most common type of which is an
authorization code.
'''javascript
server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
var code = utils.uid(16);

var ac = new AuthorizationCode(code, client.id, redirectURI, user.id, ares.scope);
ac.save(function(err) {
  if (err) { return done(err); }
  return done(null, code);
});
...
```

#### <a name="apidoc.element.oauth2orize.grant.implicit"></a>[function <span class="apidocSignatureSpan">oauth2orize.grant.</span>implicit (options, issue)](#apidoc.element.oauth2orize.grant.implicit)
- description and source-code
```javascript
function token(options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.token grant requires an issue callback'); }

  var modes = options.modes || {};
  if (!modes.fragment) {
    modes.fragment = require('../response/fragment');
  }

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }


<span class="apidocCodeCommentSpan">  /* Parse requests that request 'token' as 'response_type'.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
</span>  function request(req) {
    var clientID = req.query.client_id
      , redirectURI = req.query.redirect_uri
      , scope = req.query.scope
      , state = req.query.state;

    if (!clientID) { throw new AuthorizationError('Missing required parameter: client_id', 'invalid_request'); }
    if (typeof clientID !== 'string') { throw new AuthorizationError('Invalid parameter: client_id must be a string', 'invalid_request
'); }

    if (scope) {
      if (typeof scope !== 'string') {
        throw new AuthorizationError('Invalid parameter: scope must be a string', 'invalid_request');
      }

      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }

      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }

    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state
    };
  }

  /* Sends responses to transactions that request 'token' as 'response_type'.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */
  function response(txn, res, complete, next) {
    var mode = 'fragment'
      , respond;
    if (txn.req && txn.req.responseMode) {
      mode = txn.req.responseMode;
    }
    respond = modes[mode];

    if (!respond) {
      // http://lists.openid.net/pipermail/openid-specs-ab/Week-of-Mon-20140317/004680.html
      return next(new AuthorizationError('Unsupported response mode: ' + mode, 'unsupported_response_mode', null, 501));
    }
    if (respond && respond.validate) {
      try {
        respond.validate(txn);
      } catch(ex) {
        return next(ex);
      }
    }

    if (!txn.res.allow) {
      var params = { error: 'access_denied' };
      if (txn.req && txn.req.state) { params.state = txn.req.state; }
      return respond(txn, res, params);
    }

    function issued(err, accessToken, params) {
      if (err) { return next(err); }
      if (!accessToken) { return next(new AuthorizationError('Request denied by authorization server', 'access_denied')); }

      var tok = {};
      tok.access_token = accessToken;
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';
      if (txn.req && txn.req.state) { tok.state = txn.req.state; }
      complete(function(err) {
        if (err) { return next(err); }
        return respond(txn, res, tok);
      });
    }

    // NOTE: In contrast to an authorization code grant, redirectURI is not
    //       passed as an argument to the issue callback because it is not used
    //       as a verifier in a subsequent token exchange.  However, when
    //       issuing an implicit access tokens, an application must ensure that
    //       the redirection URI is registered, which can be done in the
    //       'validate' callback ...
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.grant.token"></a>[function <span class="apidocSignatureSpan">oauth2orize.grant.</span>token (options, issue)](#apidoc.element.oauth2orize.grant.token)
- description and source-code
```javascript
function token(options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.token grant requires an issue callback'); }

  var modes = options.modes || {};
  if (!modes.fragment) {
    modes.fragment = require('../response/fragment');
  }

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }


<span class="apidocCodeCommentSpan">  /* Parse requests that request 'token' as 'response_type'.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
</span>  function request(req) {
    var clientID = req.query.client_id
      , redirectURI = req.query.redirect_uri
      , scope = req.query.scope
      , state = req.query.state;

    if (!clientID) { throw new AuthorizationError('Missing required parameter: client_id', 'invalid_request'); }
    if (typeof clientID !== 'string') { throw new AuthorizationError('Invalid parameter: client_id must be a string', 'invalid_request
'); }

    if (scope) {
      if (typeof scope !== 'string') {
        throw new AuthorizationError('Invalid parameter: scope must be a string', 'invalid_request');
      }

      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }

      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }

    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state
    };
  }

  /* Sends responses to transactions that request 'token' as 'response_type'.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */
  function response(txn, res, complete, next) {
    var mode = 'fragment'
      , respond;
    if (txn.req && txn.req.responseMode) {
      mode = txn.req.responseMode;
    }
    respond = modes[mode];

    if (!respond) {
      // http://lists.openid.net/pipermail/openid-specs-ab/Week-of-Mon-20140317/004680.html
      return next(new AuthorizationError('Unsupported response mode: ' + mode, 'unsupported_response_mode', null, 501));
    }
    if (respond && respond.validate) {
      try {
        respond.validate(txn);
      } catch(ex) {
        return next(ex);
      }
    }

    if (!txn.res.allow) {
      var params = { error: 'access_denied' };
      if (txn.req && txn.req.state) { params.state = txn.req.state; }
      return respond(txn, res, params);
    }

    function issued(err, accessToken, params) {
      if (err) { return next(err); }
      if (!accessToken) { return next(new AuthorizationError('Request denied by authorization server', 'access_denied')); }

      var tok = {};
      tok.access_token = accessToken;
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';
      if (txn.req && txn.req.state) { tok.state = txn.req.state; }
      complete(function(err) {
        if (err) { return next(err); }
        return respond(txn, res, tok);
      });
    }

    // NOTE: In contrast to an authorization code grant, redirectURI is not
    //       passed as an argument to the issue callback because it is not used
    //       as a verifier in a subsequent token exchange.  However, when
    //       issuing an implicit access tokens, an application must ensure that
    //       the redirection URI is registered, which can be done in the
    //       'validate' callback ...
```
- example usage
```shell
...

Once a user has approved access, the authorization grant can be exchanged by the
client for an access token.

'''javascript
app.post('/token',
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  server.token(),
  server.errorHandler());
'''

[Passport](http://passportjs.org/) strategies are used to authenticate the
client, in this case using either an HTTP Basic authentication header (as
provided by [passport-http](https://github.com/jaredhanson/passport-http)) or
client credentials in the request body (as provided by
...
```



# <a name="apidoc.module.oauth2orize.server"></a>[module oauth2orize.server](#apidoc.module.oauth2orize.server)

#### <a name="apidoc.element.oauth2orize.server.server"></a>[function <span class="apidocSignatureSpan">oauth2orize.</span>server (options)](#apidoc.element.oauth2orize.server.server)
- description and source-code
```javascript
function Server(options) {
  options = options || {};
  this._reqParsers = [];
  this._resHandlers = [];
  this._errHandlers = [];
  this._exchanges = [];

  this._serializers = [];
  this._deserializers = [];
  this._txnStore = options.store || new SessionStore();
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth2orize.server.prototype"></a>[module oauth2orize.server.prototype](#apidoc.module.oauth2orize.server.prototype)

#### <a name="apidoc.element.oauth2orize.server.prototype._exchange"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>_exchange (type, req, res, cb)](#apidoc.element.oauth2orize.server.prototype._exchange)
- description and source-code
```javascript
_exchange = function (type, req, res, cb) {
  var stack = this._exchanges
    , idx = 0;

  function next(err) {
    if (err) { return cb(err); }

    var layer = stack[idx++];
    if (!layer) { return cb(); }

    try {
      debug('exchange:%s', layer.handle.name || 'anonymous');
      if (layer.type === null || layer.type === type) {
        layer.handle(req, res, next);
      } else {
        next();
      }
    } catch (ex) {
      return cb(ex);
    }
  }
  next();
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.server.prototype._parse"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>_parse (type, req, cb)](#apidoc.element.oauth2orize.server.prototype._parse)
- description and source-code
```javascript
_parse = function (type, req, cb) {
  var ultype = new UnorderedList(type)
    , stack = this._reqParsers
    , areq = {};

  if (type) { areq.type = type; }

  (function pass(i) {
    var layer = stack[i];
    if (!layer) { return cb(null, areq); }

    try {
      debug('parse:%s', layer.handle.name || 'anonymous');
      if (layer.type === null || layer.type.equalTo(ultype)) {
        var arity = layer.handle.length;
        if (arity == 1) { // sync
          var o = layer.handle(req);
          utils.merge(areq, o);
          pass(i + 1);
        } else { // async
          layer.handle(req, function(err, o) {
            if (err) { return cb(err); }
            utils.merge(areq, o);
            pass(i + 1);
          });
        }
      } else {
        pass(i + 1);
      }
    } catch (ex) {
      return cb(ex);
    }
  })(0);
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.server.prototype._respond"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>_respond (txn, res, complete, cb)](#apidoc.element.oauth2orize.server.prototype._respond)
- description and source-code
```javascript
_respond = function (txn, res, complete, cb) {
  if (cb === undefined) {
    cb = complete;
    complete = undefined;
  }

  var ultype = new UnorderedList(txn.req.type)
    , stack = this._resHandlers
    , idx = 0;

  function next(err) {
    if (err) { return cb(err); }

    var layer = stack[idx++];
    if (!layer) { return cb(); }

    try {
      debug('respond:%s', layer.handle.name || 'anonymous');
      if (layer.type === null || layer.type.equalTo(ultype)) {
        var arity = layer.handle.length;
        if (arity == 4) {
          layer.handle(txn, res, complete, next);
        } else {
          layer.handle(txn, res, next);
        }
      } else {
        next();
      }
    } catch (ex) {
      return cb(ex);
    }
  }
  next();
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.server.prototype._respondError"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>_respondError (err, txn, res, cb)](#apidoc.element.oauth2orize.server.prototype._respondError)
- description and source-code
```javascript
_respondError = function (err, txn, res, cb) {
  var ultype = new UnorderedList(txn.req.type)
    , stack = this._errHandlers
    , idx = 0;

  function next(err) {
    var layer = stack[idx++];
    if (!layer) { return cb(err); }

    try {
      debug('error:%s', layer.handle.name || 'anonymous');
      if (layer.type === null || layer.type.equalTo(ultype)) {
        layer.handle(err, txn, res, next);
      } else {
        next(err);
      }
    } catch (ex) {
      return cb(ex);
    }
  }
  next(err);
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.server.prototype.authorization"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorization (options, validate, immediate)](#apidoc.element.oauth2orize.server.prototype.authorization)
- description and source-code
```javascript
authorization = function (options, validate, immediate) {
  return authorization(this, options, validate, immediate);
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.server.prototype.authorizationError"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorizationError (options)](#apidoc.element.oauth2orize.server.prototype.authorizationError)
- description and source-code
```javascript
authorizationError = function (options) {
  var loader = transactionLoader(this, options);

  return [
    function transactionLoaderErrorWrapper(err, req, res, next) {
      loader(req, res, function(ierr) {
        return next(err);
      });
    },
    authorizationErrorHandler(this, options)
  ];
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.server.prototype.authorizationErrorHandler"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorizationErrorHandler (options)](#apidoc.element.oauth2orize.server.prototype.authorizationErrorHandler)
- description and source-code
```javascript
authorizationErrorHandler = function (options) {
  var loader = transactionLoader(this, options);

  return [
    function transactionLoaderErrorWrapper(err, req, res, next) {
      loader(req, res, function(ierr) {
        return next(err);
      });
    },
    authorizationErrorHandler(this, options)
  ];
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.server.prototype.authorize"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorize (options, validate, immediate)](#apidoc.element.oauth2orize.server.prototype.authorize)
- description and source-code
```javascript
authorize = function (options, validate, immediate) {
  return authorization(this, options, validate, immediate);
}
```
- example usage
```shell
...
When a client requests authorization, it will redirect the user to an
authorization endpoint.  The server must authenticate the user and obtain
their permission.

'''javascript
app.get('/dialog/authorize',
login.ensureLoggedIn(),
server.authorize(function(clientID, redirectURI, done) {
  Clients.findOne(clientID, function(err, client) {
    if (err) { return done(err); }
    if (!client) { return done(null, false); }
    if (!client.redirectUri != redirectURI) { return done(null, false); }
    return done(null, client, client.redirectURI);
  });
}),
...
```

#### <a name="apidoc.element.oauth2orize.server.prototype.authorizeError"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>authorizeError (options)](#apidoc.element.oauth2orize.server.prototype.authorizeError)
- description and source-code
```javascript
authorizeError = function (options) {
  var loader = transactionLoader(this, options);

  return [
    function transactionLoaderErrorWrapper(err, req, res, next) {
      loader(req, res, function(ierr) {
        return next(err);
      });
    },
    authorizationErrorHandler(this, options)
  ];
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.server.prototype.decision"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>decision (options, parse)](#apidoc.element.oauth2orize.server.prototype.decision)
- description and source-code
```javascript
decision = function (options, parse) {
  if (options && options.loadTransaction === false) {
    return decision(this, options, parse);
  }
  return [transactionLoader(this, options), decision(this, options, parse)];
}
```
- example usage
```shell
...
authorization proceeds.  At that point, the application renders a dialog
asking the user to grant access.  The resulting form submission is processed
using 'decision' middleware.

'''javascript
app.post('/dialog/authorize/decision',
   login.ensureLoggedIn(),
   server.decision());
'''

Based on the grant type requested by the client, the appropriate grant
module registered above will be invoked to issue an authorization code.

#### Session Serialization
...
```

#### <a name="apidoc.element.oauth2orize.server.prototype.deserializeClient"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>deserializeClient (fn, done)](#apidoc.element.oauth2orize.server.prototype.deserializeClient)
- description and source-code
```javascript
deserializeClient = function (fn, done) {
  if (typeof fn === 'function') {
    return this._deserializers.push(fn);
  }

  // private implementation that traverses the chain of deserializers,
  // attempting to deserialize a client
  var obj = fn;

  var stack = this._deserializers;
  (function pass(i, err, client) {
    // deserializers use 'pass' as an error to skip processing
    if ('pass' === err) { err = undefined; }
    // an error or deserialized client was obtained, done
    if (err || client) { return done(err, client); }
    // a valid client existed when establishing the session, but that client has
    // since been deauthorized
    if (client === null || client === false) { return done(null, false); }

    var layer = stack[i];
    if (!layer) {
      return done(new Error('Failed to deserialize client. Register deserialization function using deserializeClient().'));
    }

    try {
      layer(obj, function(e, c) { pass(i + 1, e, c); } );
    } catch (ex) {
      return done(ex);
    }
  })(0);
}
```
- example usage
```shell
...
by ID when deserializing.

'''javascript
server.serializeClient(function(client, done) {
  return done(null, client.id);
});

server.deserializeClient(function(id, done) {
  Clients.findOne(id, function(err, client) {
    if (err) { return done(err); }
    return done(null, client);
  });
});
'''
...
```

#### <a name="apidoc.element.oauth2orize.server.prototype.errorHandler"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>errorHandler (options)](#apidoc.element.oauth2orize.server.prototype.errorHandler)
- description and source-code
```javascript
errorHandler = function (options) {
  return errorHandler(options);
}
```
- example usage
```shell
...
Once a user has approved access, the authorization grant can be exchanged by the
client for an access token.

'''javascript
app.post('/token',
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  server.token(),
  server.errorHandler());
'''

[Passport](http://passportjs.org/) strategies are used to authenticate the
client, in this case using either an HTTP Basic authentication header (as
provided by [passport-http](https://github.com/jaredhanson/passport-http)) or
client credentials in the request body (as provided by
[passport-oauth2-client-password](https://github.com/jaredhanson/passport-oauth2-client-password)).
...
```

#### <a name="apidoc.element.oauth2orize.server.prototype.exchange"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>exchange (type, fn)](#apidoc.element.oauth2orize.server.prototype.exchange)
- description and source-code
```javascript
exchange = function (type, fn) {
  if (typeof type == 'function') {
    fn = type;
    type = fn.name;
  }
  if (type === '*') { type = null; }

  debug('register exchanger %s %s', type || '*', fn.name || 'anonymous');
  this._exchanges.push({ type: type, handle: fn });
  return this;
}
```
- example usage
```shell
...

#### Register Exchanges

After a client has obtained an authorization grant from the user, that grant can
be exchanged for an access token.

'''javascript
server.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, done) {
  AuthorizationCode.findOne(code, function(err, code) {
if (err) { return done(err); }
if (client.id !== code.clientId) { return done(null, false); }
if (redirectURI !== code.redirectUri) { return done(null, false); }

var token = utils.uid(256);
var at = new AccessToken(token, code.userId, code.clientId, code.scope);
...
```

#### <a name="apidoc.element.oauth2orize.server.prototype.grant"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>grant (type, phase, fn)](#apidoc.element.oauth2orize.server.prototype.grant)
- description and source-code
```javascript
grant = function (type, phase, fn) {
  if (typeof type == 'object') {
    // sig: grant(mod)
    var mod = type;
    if (mod.request) { this.grant(mod.name, 'request', mod.request); }
    if (mod.response) { this.grant(mod.name, 'response', mod.response); }
    if (mod.error) { this.grant(mod.name, 'error', mod.error); }
    return this;
  }
  if (typeof phase == 'object') {
    // sig: grant(type, mod)
    var mod = phase;
    if (mod.request) { this.grant(type, 'request', mod.request); }
    if (mod.response) { this.grant(type, 'response', mod.response); }
    if (mod.error) { this.grant(type, 'error', mod.error); }
    return this;
  }

  if (typeof phase == 'function') {
    // sig: grant(type, fn)
    fn = phase;
    phase = 'request';
  }
  if (type === '*') { type = null; }
  if (type) { type = new UnorderedList(type); }

  if (phase == 'request') {
    debug('register request parser %s %s', type || '*', fn.name || 'anonymous');
    this._reqParsers.push({ type: type, handle: fn });
  } else if (phase == 'response') {
    debug('register response handler %s %s', type || '*', fn.name || 'anonymous');
    this._resHandlers.push({ type: type, handle: fn });
  } else if (phase == 'error') {
    debug('register error handler %s %s', type || '*', fn.name || 'anonymous');
    this._errHandlers.push({ type: type, handle: fn });
  }
  return this;
}
```
- example usage
```shell
...

#### Register Grants

A client must obtain permission from a user before it is issued an access token.
This permission is known as a grant, the most common type of which is an
authorization code.
'''javascript
server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
var code = utils.uid(16);

var ac = new AuthorizationCode(code, client.id, redirectURI, user.id, ares.scope);
ac.save(function(err) {
  if (err) { return done(err); }
  return done(null, code);
});
...
```

#### <a name="apidoc.element.oauth2orize.server.prototype.resume"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>resume (options, immediate)](#apidoc.element.oauth2orize.server.prototype.resume)
- description and source-code
```javascript
resume = function (options, immediate) {
  if (options && options.loadTransaction === false) {
    return resume(this, options, immediate);
  }
  return [transactionLoader(this, options), resume(this, options, immediate)];
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.server.prototype.serializeClient"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>serializeClient (fn, done)](#apidoc.element.oauth2orize.server.prototype.serializeClient)
- description and source-code
```javascript
serializeClient = function (fn, done) {
  if (typeof fn === 'function') {
    return this._serializers.push(fn);
  }

  // private implementation that traverses the chain of serializers, attempting
  // to serialize a client
  var client = fn;

  var stack = this._serializers;
  (function pass(i, err, obj) {
    // serializers use 'pass' as an error to skip processing
    if ('pass' === err) { err = undefined; }
    // an error or serialized object was obtained, done
    if (err || obj) { return done(err, obj); }

    var layer = stack[i];
    if (!layer) {
      return done(new Error('Failed to serialize client. Register serialization function using serializeClient().'));
    }

    try {
      layer(client, function(e, o) { pass(i + 1, e, o); } );
    } catch (ex) {
      return done(ex);
    }
  })(0);
}
```
- example usage
```shell
...
Obtaining the user's authorization involves multiple request/response pairs.
During this time, an OAuth 2.0 transaction will be serialized to the session.
Client serialization functions are registered to customize this process, which
will typically be as simple as serializing the client ID, and finding the client
by ID when deserializing.

'''javascript
server.serializeClient(function(client, done) {
return done(null, client.id);
});

server.deserializeClient(function(id, done) {
Clients.findOne(id, function(err, client) {
  if (err) { return done(err); }
  return done(null, client);
...
```

#### <a name="apidoc.element.oauth2orize.server.prototype.token"></a>[function <span class="apidocSignatureSpan">oauth2orize.server.prototype.</span>token (options)](#apidoc.element.oauth2orize.server.prototype.token)
- description and source-code
```javascript
token = function (options) {
  return token(this, options);
}
```
- example usage
```shell
...

Once a user has approved access, the authorization grant can be exchanged by the
client for an access token.

'''javascript
app.post('/token',
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  server.token(),
  server.errorHandler());
'''

[Passport](http://passportjs.org/) strategies are used to authenticate the
client, in this case using either an HTTP Basic authentication header (as
provided by [passport-http](https://github.com/jaredhanson/passport-http)) or
client credentials in the request body (as provided by
...
```



# <a name="apidoc.module.oauth2orize.unorderedlist"></a>[module oauth2orize.unorderedlist](#apidoc.module.oauth2orize.unorderedlist)

#### <a name="apidoc.element.oauth2orize.unorderedlist.unorderedlist"></a>[function <span class="apidocSignatureSpan">oauth2orize.</span>unorderedlist (items)](#apidoc.element.oauth2orize.unorderedlist.unorderedlist)
- description and source-code
```javascript
function UnorderedList(items) {
  if (typeof items == 'string') {
    items = items.split(' ');
  }
  this._items = items || [];
  this.__defineGetter__('length', this._length);
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth2orize.unorderedlist.prototype"></a>[module oauth2orize.unorderedlist.prototype](#apidoc.module.oauth2orize.unorderedlist.prototype)

#### <a name="apidoc.element.oauth2orize.unorderedlist.prototype._length"></a>[function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>_length ()](#apidoc.element.oauth2orize.unorderedlist.prototype._length)
- description and source-code
```javascript
_length = function () {
  return this._items.length;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.unorderedlist.prototype.contains"></a>[function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>contains (val)](#apidoc.element.oauth2orize.unorderedlist.prototype.contains)
- description and source-code
```javascript
contains = function (val) {
  return this._items.indexOf(val) != -1;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.unorderedlist.prototype.containsAny"></a>[function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>containsAny (arr)](#apidoc.element.oauth2orize.unorderedlist.prototype.containsAny)
- description and source-code
```javascript
containsAny = function (arr) {
  for (var i = 0, len = arr.length; i < len; i++) {
    if (this._items.indexOf(arr[i]) != -1) { return true; }
  }
  return false;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth2orize.unorderedlist.prototype.equalTo"></a>[function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>equalTo (other)](#apidoc.element.oauth2orize.unorderedlist.prototype.equalTo)
- description and source-code
```javascript
equalTo = function (other) {
  if (!(other instanceof UnorderedList)) {
    other = new UnorderedList(other);
  }

  if (this.length != other.length) { return false; }
  for (var i = 0, len = this._items.length; i < len; i++) {
    var item = this._items[i];
    if (other._items.indexOf(item) == -1) {
      return false;
    }
  }
  return true;
}
```
- example usage
```shell
...

  (function pass(i) {
var layer = stack[i];
if (!layer) { return cb(null, areq); }

try {
  debug('parse:%s', layer.handle.name || 'anonymous');
  if (layer.type === null || layer.type.equalTo(ultype)) {
    var arity = layer.handle.length;
    if (arity == 1) { // sync
      var o = layer.handle(req);
      utils.merge(areq, o);
      pass(i + 1);
    } else { // async
      layer.handle(req, function(err, o) {
...
```

#### <a name="apidoc.element.oauth2orize.unorderedlist.prototype.toString"></a>[function <span class="apidocSignatureSpan">oauth2orize.unorderedlist.prototype.</span>toString ()](#apidoc.element.oauth2orize.unorderedlist.prototype.toString)
- description and source-code
```javascript
toString = function () {
  return this._items.join(' ');
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth2orize.utils"></a>[module oauth2orize.utils](#apidoc.module.oauth2orize.utils)

#### <a name="apidoc.element.oauth2orize.utils.merge"></a>[function <span class="apidocSignatureSpan">oauth2orize.utils.</span>merge (a, b)](#apidoc.element.oauth2orize.utils.merge)
- description and source-code
```javascript
merge = function (a, b){
  if (a && b) {
    for (var key in b) {
      a[key] = b[key];
    }
  }
  return a;
}
```
- example usage
```shell
...

    try {
debug('parse:%s', layer.handle.name || 'anonymous');
if (layer.type === null || layer.type.equalTo(ultype)) {
  var arity = layer.handle.length;
  if (arity == 1) { // sync
    var o = layer.handle(req);
    utils.merge(areq, o);
    pass(i + 1);
  } else { // async
    layer.handle(req, function(err, o) {
      if (err) { return cb(err); }
      utils.merge(areq, o);
      pass(i + 1);
    });
...
```

#### <a name="apidoc.element.oauth2orize.utils.uid"></a>[function <span class="apidocSignatureSpan">oauth2orize.utils.</span>uid (length, cb)](#apidoc.element.oauth2orize.utils.uid)
- description and source-code
```javascript
function uid(length, cb) {

  if (typeof cb === 'undefined') {
    return tostr(crypto.pseudoRandomBytes(length));
  } else {
    crypto.pseudoRandomBytes(length, function(err, bytes) {
       if (err) return cb(err);
       cb(null, tostr(bytes));
    })
  }
}
```
- example usage
```shell
...
#### Register Grants

A client must obtain permission from a user before it is issued an access token.
This permission is known as a grant, the most common type of which is an
authorization code.
'''javascript
server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
  var code = utils.uid(16);

  var ac = new AuthorizationCode(code, client.id, redirectURI, user.id, ares.scope);
  ac.save(function(err) {
    if (err) { return done(err); }
    return done(null, code);
  });
}));
...
```



# misc
- this document was created with [utility2](https://github.com/kaizhu256/node-utility2)
