var passport = require('passport');

exports.callback = function(req, token, tokenSecret, profile, done) {
    exports.User.findOrCreate({
        twitterId: profile.id,
        profile: profile,
        twToken: token
    }, function (err, user) {
        req.session.twToken = token;
        req.session.loginTool = 'twitter';
        req.session.logged = true;
        return done(err, user);
    });
};

exports.init = function (conf, app) {
    var Strategy = require('passport-twitter').Strategy;
    passport.use(new Strategy({
        consumerKey: conf.twitter.apiKey,
        consumerSecret: conf.twitter.secret,
        callbackURL: conf.baseURL + 'auth/twitter/callback',
        passReqToCallback: true
    }, exports.callback));

    app.get((app.settings.passportRoot || '') + '/auth/twitter',
        passport.authenticate('twitter'));

    app.get((app.settings.passportRoot || '') + '/auth/twitter/callback',
        passport.authenticate('twitter', {
            failureRedirect: conf.failureRedirect || '/'
        }), exports.redirectOnSuccess);

};
