'use strict';

/**
 * Module dependencies.
 */
var passport 		= require('passport'),
	url 			= require('url'),
	ServantStrategy = require('passport-servant').Strategy,
	config 			= require('../config'),
	users 			= require('../../app/controllers/users');

module.exports = function() {
	// Use servant strategy
	passport.use(new ServantStrategy({
			authorizationURL:   'http://servant.co/oauth/authorize',
			tokenURL:           'http://www.servant.co/oauth/authorize/decision',
			clientID:     		config.servant.clientID,
			clientSecret:  		config.servant.clientSecret,
			callbackURL:     	config.servant.callbackURL
		},
		function(accessToken, refreshToken, profile, done) {
		    User.findOrCreate({ exampleId: profile.id }, function (err, user) {
		      return done(err, user);
		    });
		}
	));

	passport.use(new ExampleStrategy({
      // see https://github.com/jaredhanson/oauth2orize/blob/master/examples/all-grants/db/clients.js
      clientID: opts.clientId
    , clientSecret: opts.clientSecret
    , callbackURL: lConf.protocol + "://" + lConf.host + "/auth/example-oauth2orize/callback"
    }
  , function (accessToken, refreshToken, profile, done) {
      User.findOrCreate({ profile: profile }, function (err, user) {
        user.accessToken = accessToken;
        return done(err, user);
      });
    }
  ));


	
};