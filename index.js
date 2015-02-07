var Resource = require('deployd/lib/resource')
  , Script = require('deployd/lib/script')
  , UserCollection = require('deployd/lib/resources/user-collection')
  , internalClient = require('deployd/lib/internal-client')
  , util = require('util')
  , url = require('url')
  , debug = require('debug')('dpd-passport')

  // Stetegies
  , LocalStrategy = require('passport-local').Strategy
  , TwitterStrategy = require('passport-twitter').Strategy
  , FacebookStrategy = require('passport-facebook').Strategy
  , GitHubStrategy = require('passport-github').Strategy
  , GoogleStrategy = require('passport-google-oauth').OAuth2Strategy

  // Globals
  , DEFAULT_SALT_LEN = 256
  , CALLBACK_URL = 'callback';

function AuthResource() {
    Resource.apply(this, arguments);

    // read and parse config
    var config = this.config;
    config.SALT_LEN = config.SALT_LEN || DEFAULT_SALT_LEN;
    config.baseURL = config.baseURL || process.env.DPD_PASSPORT_BASEURL;

    config.allowTwitter = config.allowTwitter && config.baseURL && config.twitterConsumerKey && config.twitterConsumerSecret;
    config.allowFacebook = config.allowFacebook && config.baseURL && config.facebookAppId && config.facebookAppSecret;
    config.allowGitHub = config.allowGitHub && config.baseURL && config.githubClientId && config.githubClientSecret;
    config.allowGoogle = config.allowGoogle && config.baseURL && config.googleClientId && config.googleClientSecret;
}
util.inherits(AuthResource, Resource);

AuthResource.label = "Passport-Auth";
AuthResource.defaultPath = '/auth';
module.exports = AuthResource;

AuthResource.prototype.clientGeneration = false;

AuthResource.prototype.initPassport = function() {
    if(this.initialized) return;

    var config = this.config,
        dpd = internalClient.build(process.server, {isRoot: true}, []),
        userCollection = process.server.resources.filter(function(res) {return res.config.type === 'UserCollection'})[0],
        passport = (this.passport = require('passport'));



    // Will be called when socialLogins are done
    // Check for existing user and update
    // or create new user and insert
    var socialAuthCallback = function(token, tokenSecret, profile, done) {
        debug('Login callback - profile: %j', profile);

        userCollection.store.first({socialAccountId: profile.id}, function(err, user) {
            if(err) { return done(err); }

            var saveUser = user || {
                // these properties will only be set on first insert
                socialAccountId: profile.id,
                socialAccount: profile.provider,
                name: profile.displayName
            };

            // update the profile on every login, so that we always have the latest info available
            saveUser.profile = profile;

            if(user) {
                debug('updating existing user w/ id', user.id);
            } else {
                debug('creating new user w/ socialAccountId=%s', saveUser.socialAccountId);

                // we need to fake the password here, because deployd will force us to on create
                // but we'll clear that later
                saveUser.username = saveUser.socialAccount + '_' + saveUser.socialAccountId;
                saveUser.password = saveUser.username;
            }
            dpd.users.put(saveUser, function(res, err) {
                if(err) { return done(err); }

                // before actually progressing the request, we need to clear username + password for social users
                userCollection.store.update({id: res.id}, {username: null, password: null}, function() {
                    done(null, res||saveUser);
                });
            });
        });
    };

    if(config.allowLocal) {
        passport.use(new LocalStrategy(
          function(username, password, done) {
            userCollection.store.first({username: username}, function(err, user) {
                if(err) { return done(err); }

                if(user) {
                    var salt = user.password.substr(0, config.SALT_LEN)
                      , hash = user.password.substr(config.SALT_LEN);

                    if(hash === UserCollection.prototype.hash(password, salt)) {
                        return done(null, user);
                    }
                }

                return done(null, false, { message: 'Invalid password' });
            });
          }
        ));
    }

    if(config.allowTwitter) {
        var cbURL = url.resolve(config.baseURL, this.path + '/twitter/' + CALLBACK_URL);

        debug('Initializing Twitter Login, cb: %s', cbURL);
        passport.use(new TwitterStrategy({
            consumerKey: config.twitterConsumerKey,
            consumerSecret: config.twitterConsumerSecret,
            callbackURL: cbURL,
            sessionKey: 'data'
          },
          socialAuthCallback
        ));
    }

    if(config.allowFacebook) {
        var cbURL = url.resolve(config.baseURL, this.path + '/facebook/' + CALLBACK_URL);

        debug('Initializing Facebook Login, cb: %s', cbURL);
        passport.use(new FacebookStrategy({
            clientID: config.facebookAppId,
            clientSecret: config.facebookAppSecret,
            callbackURL: cbURL
          },
          socialAuthCallback
        ));
    }

    if(config.allowGitHub) {
        var cbURL = url.resolve(config.baseURL, this.path + '/github/' + CALLBACK_URL);

        debug('Initializing GitHub Login, cb: %s', cbURL);
        passport.use(new GitHubStrategy({
            clientID: config.githubClientId,
            clientSecret: config.githubClientSecret,
            callbackURL: cbURL
          },
          socialAuthCallback
        ));
    }

    if(config.allowGoogle) {
        var cbURL = url.resolve(config.baseURL, this.path + '/google/' + CALLBACK_URL);

        debug('Initializing Google Login, cb: %s', cbURL);
        passport.use(new GoogleStrategy({
            clientID: config.googleClientId,
            clientSecret: config.googleClientSecret,
            callbackURL: cbURL
          },

          socialAuthCallback
        ));
    }

    this.initialized = true;
}

var sendResponse = function(ctx, err, disableSessionId) {
    var sessionData = ctx.session.data;
    if(sessionData.redirectURL) {
        var redirectURL = url.parse(sessionData.redirectURL, true);
        // delete search so that query is used
        delete redirectURL.search;

        // make sure query is inited
        redirectURL.query = redirectURL.query || {};

        if(err) {
            redirectURL.query.success = false;
            redirectURL.query.error = err;
        } else {
            // append user + session id to the redirect url
            redirectURL.query.success = true;

            if(!disableSessionId) {
                redirectURL.query.sid = sessionData.id;
                redirectURL.query.uid = sessionData.uid;
            }
        }

        var redirectURLString = '';
        try {
            redirectURLString = url.format(redirectURL);
        } catch(ex) {
            console.warn('An error happened while formatting the redirectURL', ex);
        }

        // redirect the user
        ctx.res.setHeader("Location", redirectURLString);
        ctx.res.statusCode = 302;

        ctx.done(null, 'This page has moved to ' + redirectURLString);
    } else {
        if(err) {
            ctx.res.statusCode = 401;
            return ctx.done('bad credentials');
        } else {
            ctx.done(err, sessionData);
        }
    }
}
AuthResource.prototype.handle = function (ctx, next) {
    var config = this.config;
    
    // globally handle logout
    if(ctx.url === '/logout') {
        if (ctx.res.cookies) ctx.res.cookies.set('sid', null, {overwrite: true});
        ctx.session.remove(ctx.done);
        return;
    }

    var parts = ctx.url.split('/').filter(function(p) {
        // filters out all empty parts
        return p;
    });

    // determine requested module
    var requestedModule, options = {};
    switch(parts[0]) {
        case 'login':
            if(ctx.method === 'POST' && this.config.allowLocal) {
                requestedModule = 'local';
            }
            break;
        case 'twitter':
            if(this.config.allowTwitter) {
                requestedModule = 'twitter';
            }
            break;
        case 'facebook':
            if(this.config.allowFacebook) {
                requestedModule = 'facebook';
                if(this.config.facebookScope) {
                    try {
                        options.scope = JSON.parse(this.config.facebookScope);
                    } catch(ex) {
                        debug('Error parsing the facebookScope');
                    }
                }
            }
            break;
        case 'github':
            if(this.config.allowGitHub) {
                requestedModule = 'github';
                if(this.config.githubScope) {
                    try {
                        options.scope = JSON.parse(this.config.githubScope);
                    } catch(ex) {
                        debug('Error parsing the githubScope')
                    }
                }
            }
            break;
        case 'google':
            if(this.config.allowGoogle) {
                requestedModule = 'google';
                options.scope = this.config.googleScope || 'profile email';
            }
            break;
        default:
            break;
    }

    if(requestedModule) {
        // save the redirectURL for later use
        if(ctx.query.redirectURL && this.config.allowedRedirectURLs) {
            try {
                this.regEx = this.regEx || new RegExp(this.config.allowedRedirectURLs, 'i');

                if(ctx.query.redirectURL.match(this.regEx)) {
                    // save this info into the users session, so that we can access it later (even if the user was redirected to facebook)
                    ctx.session.set({redirectURL: ctx.query.redirectURL});
                } else {
                    debug(ctx.query.redirectURL, 'did not match', this.config.allowedRedirectURLs);
                }
            } catch(ex) {
                debug('Error parsing RedirectURL Regex!', ex);
            }
        }

        this.initPassport();
        this.passport.authenticate(requestedModule, options, function(err, user, info) {
            if (err || !user) {
                debug('passport reported error: ', err, user, info);
                return sendResponse(ctx, 'bad credentials', config.disableSessionId);
            }

			if (ctx.res.cookies) {
                ctx.res.cookies.set('sid', ctx.session.sid, {overwrite: true});
            }

            ctx.session.set({path: '/users', uid: user.id}).save(function(err, sessionData) {
                return sendResponse(ctx, err, config.disableSessionId);
            });
        })(ctx.req, ctx.res, ctx.next||ctx.done);
    } else {
        // nothing matched, sorry
        debug('no module found: ', parts[0]);
        return sendResponse(ctx, 'bad credentials', config.disableSessionId);
    }
};

AuthResource.basicDashboard = {
  settings: [{
    name        : 'SALT_LEN',
    type        : 'numeric',
    description : 'Length of the Password salt that is used by deployd. Do not change if you don\'t know what this is or your users may not login anymore! Defaults to 256.'
  },{
    name        : 'baseURL',
    type        : 'text',
    description : 'Specify the Base URL of your site (http://www.your-page.com/) that is used for callbacks. *Required when using any OAuth Login!* Defaults to env variable DPD_PASSPORT_BASEURL.'
  },{
    name        : 'allowedRedirectURLs',
    type        : 'text',
    description : 'Specify a regular expression for which redirect URLs you want to allow. Supply as JS-Regex: "^http://www\.your-page.com/.*$", matching is always done case-insensitive. Defaults to "" (i.e. NO redirects will be allowed!)'
  },{
    name        : 'disableSessionId',
    type        : 'checkbox',
    description : 'Disable appending the Session Id to the redirect URL. This is a security measure for the web. You can access the Session Id from the Cookie-Header.'
  },{
    name        : 'allowLocal',
    type        : 'checkbox',
    description : 'Allow users to login via Username + Password'
  },{
    name        : 'allowTwitter',
    type        : 'checkbox',
    description : 'Allow users to login via Twitter (requires Twitter Key and Secret!)'
  },{
    name        : 'allowFacebook',
    type        : 'checkbox',
    description : 'Allow users to login via Facebook (requires Facebook Id and Secret!)'
  },{
    name        : 'allowGitHub',
    type        : 'checkbox',
    description : 'Allow users to login via GitHub (requires GitHub Id and Secret!)'
  },{
    name        : 'allowGoogle',
    type        : 'checkbox',
    description : 'Allow users to login via Google'
  },{
    name        : 'twitterConsumerKey',
    type        : 'text'/*,
    description : 'TWITTER_CONSUMER_KEY'*/
  }, {
    name        : 'twitterConsumerSecret',
    type        : 'text'/*,
    description : 'TWITTER_CONSUMER_SECRET'*/
  },{
    name        : 'facebookAppId',
    type        : 'text'/*,
    description : 'TWITTER_CONSUMER_KEY'*/
  }, {
    name        : 'facebookAppSecret',
    type        : 'text'/*,
    description : 'TWITTER_CONSUMER_SECRET'*/
  }, {
    name        : 'facebookScope',
    type        : 'text',
    description : 'If your application needs extended permissions, they can be requested here. Supply as JS-Array: "[\'read_stream\']"'
  }, {
    name        : 'githubClientId',
    type        : 'text'/*,
    description : 'TODO'*/
  }, {
    name        : 'githubClientSecret',
    type        : 'text'/*,
    description : 'TODO'*/
  }, {
    name        : 'githubScope',
    type        : 'text',
    description : 'If your application needs extended permissions, they can be requested here. Supply as JS-Array: "[\'repo\']"'
  }, {
    name        : 'googleClientId',
    type        : 'text'
  }, {
    name        : 'googleClientSecret',
    type        : 'text'
  }, {
    name        : 'googleScope',
    type        : 'text',
    description : 'defaults to "profile email"'
  }
  ]
};
