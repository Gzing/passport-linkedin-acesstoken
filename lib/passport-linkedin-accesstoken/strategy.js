/**
 * Module dependencies.
 */
var util = require('util')
  , url = require('url')
  , querystring = require('querystring')
  , OAuthStrategy = require('passport-oauth').OAuthStrategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


function LinkedInTokenStrategy(options, verify) {
  options = options || {};
  options.requestTokenURL = options.requestTokenURL || 'https://api.linkedin.com/uas/oauth/requestToken';
  options.accessTokenURL = options.accessTokenURL || 'https://api.linkedin.com/uas/oauth/accessToken';
  options.userAuthorizationURL = options.userAuthorizationURL || 'https://www.linkedin.com/uas/oauth/authenticate';
  options.sessionKey = options.sessionKey || 'oauth:linkedin';

  OAuthStrategy.call(this, options, verify);
  this.name = 'linkedin-token';
  this._profileFields = options.profileFields || null;
  
  // LinkedIn accepts an extended "scope" parameter when obtaining a request.
  // Unfortunately, it wants this as a URL query parameter, rather than encoded
  // in the POST body (which is the more established and supported mechanism of
  // extending OAuth).
  //
  // Monkey-patch the underlying node-oauth implementation to add these extra
  // parameters as URL query parameters.
  this._oauth.getOAuthRequestToken= function( extraParams, callback ) {

     if( typeof extraParams == "function" ){
       callback = extraParams;
       extraParams = {};
     }
     
    var requestUrl = this._requestUrl;
    if (extraParams.scope) {
      requestUrl = requestUrl += ('?scope=' + extraParams.scope);
      delete extraParams.scope;
    }
     
    // Callbacks are 1.0A related 
    if( this._authorize_callback ) {
      extraParams["oauth_callback"]= this._authorize_callback;
    }
    this._performSecureRequest( null, null, this._clientOptions.requestTokenHttpMethod, requestUrl, extraParams, null, null, function(error, data, response) {
      if( error ) callback(error);
      else {
        var results= querystring.parse(data);
  
        var oauth_token= results["oauth_token"];
        var oauth_token_secret= results["oauth_token_secret"];
        delete results["oauth_token"];
        delete results["oauth_token_secret"];
        callback(null, oauth_token, oauth_token_secret,  results );
      }


    });
  }
}

/**
 * Inherit from `OAuthStrategy`.
 */
util.inherits(LinkedInTokenStrategy, OAuthStrategy);

/**
 * Authenticate request by delegating to LinkedIn using OAuth.
 *
 * @param {Object} req
 * @api protected
 */
LinkedInTokenStrategy.prototype.authenticate = function(req, options) {
  // When a user denies authorization on LinkedIn, they are presented with a
  // link to return to the application in the following format:
  //
  //     http://www.example.com/auth/linkedin/callback?oauth_problem=user_refused
  //
  // Following the link back to the application is interpreted as an
  // authentication failure.
  if (req.query && req.query.oauth_problem) {
    return this.fail();
  }

  var self = this;
  var token = req.body.oauth_token || req.query.oauth_token;
  var tokenSecret = req.body.oauth_token_secret || req.query.oauth_token_secret;
  var userId = req.body.user_id || req.query.user_id;
  var params = {};

  self._loadUserProfile(token, tokenSecret, params, function(err, profile){
    if(err) { return self.error(err); };
    function verified(err, user, info) {
      if(err) {return self.error(err);}
      if(!user) {return self.fail(info);}
      self.success(user, info);
    }

    if(self._passReqToCallback) {
      var arity = self._verify.length;
      if(arity == 6) {
        self._verify(req, token, tokenSecret, params, profile, verified);
      } else {
        self._verify(req, token, tokenSecret, profile, verified);
      }
    } else {
      var arity = self._verify.length;
      if (arity == 5){
        self._verify(token, tokenSecret, params, profile, verified);
      } else {
        self._verify(token, tokenSecret, params, verified);
      }
    }

  });
  
}

/**
 * Retrieve user profile from LinkedIn.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`
 *   - `displayName`
 *   - `name.familyName`
 *   - `name.givenName`
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
LinkedInTokenStrategy.prototype.userProfile = function(token, tokenSecret, params, done) {
  var url = 'https://api.linkedin.com/v1/people/~:(id,first-name,last-name)?format=json';

  if (this._profileFields) {
    var fields = this._convertProfileFields(this._profileFields);
    url = 'https://api.linkedin.com/v1/people/~:(' + fields + ')?format=json';
  }

  this._oauth.get(url, token, tokenSecret, function (err, body, res) {

    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
    
    try {
      var json = JSON.parse(body);
      
      var profile = { provider: 'linkedin' };
      profile.id = json.id;
      profile.displayName = json.firstName + ' ' + json.lastName;
      profile.name = { familyName: json.lastName,
                       givenName: json.firstName };
      if (json.emailAddress) { profile.emails = [{ value: json.emailAddress }]; }
      
      profile._raw = body;
      profile._json = json;
      
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}

/**
 * Return extra LinkedIn-specific parameters to be included in the request token
 * request.
 *
 * References:
 *   https://developer.linkedin.com/documents/authentication#granting
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
LinkedInTokenStrategy.prototype.requestTokenParams = function(options) {
  var params = {};
  
  var scope = options.scope;
  if (scope) {
    if (Array.isArray(scope)) { scope = scope.join('+'); }
    params['scope'] = scope;
  }
  return params;
}

LinkedInTokenStrategy.prototype._convertProfileFields = function(profileFields) {
  var map = {
    'id':          'id',
    'name':       ['first-name', 'last-name'],
    'emails':      'email-address'
  };
  
  var fields = [];
  
  profileFields.forEach(function(f) {
    // return raw LinkedIn profile field to support the many fields that don't
    // map cleanly to Portable Contacts
    if (typeof map[f] === 'undefined') { return fields.push(f); };

    if (Array.isArray(map[f])) {
      Array.prototype.push.apply(fields, map[f]);
    } else {
      fields.push(map[f]);
    }
  });

  return fields.join(',');
}


/**
 * Expose `LinkedInTokenStrategy`.
 */
module.exports = LinkedInTokenStrategy;
