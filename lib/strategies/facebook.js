var passport = require('passport');

exports.callback = function(req, token, tokenSecret, profile, done) {
    exports.User.findOrCreate({
        facebookId: profile.id,
        profile: profile,
        fbToken: token
    }, function (err, user) {
        req.session.fbToken = token;
        req.session.loginTool = 'facebook';
        req.session.logged = true;
        return done(err, user);
    });
};

exports.init = function (conf, app) {
    var Strategy = require('passport-facebook').Strategy;
    passport.use(new Strategy({
        clientID: conf.facebook.apiKey,
        clientSecret: conf.facebook.secret,
        callbackURL: conf.baseURL + 'auth/facebook/callback',
        passReqToCallback: true
    }, exports.callback));

    app.get((app.settings.passportRoot || '') + '/auth/facebook',
        passport.authenticate('facebook', { scope: [ 'email' ] }));

    app.get((app.settings.passportRoot || '') + '/auth/facebook/callback',
        passport.authenticate('facebook', {
            failureRedirect: conf.failureRedirect || '/'
        }), exports.redirectOnSuccess);

};
