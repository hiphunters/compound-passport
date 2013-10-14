var passport = require('passport')
    , LocalStrategy = require('passport-local').Strategy;

exports.callback = function (req, email, password, done) { 
    exports.User.findOrCreate({
        email: email,
        password: password
    }, function (err, user) {
        if (err) { 
            return done(err); 
        }
        if (!user) { 
            return done(err, false); 
        }
        if(!password || !user.password){
            return done(err, false);
        }else if(password == user.password){
            req.session.loginTool = 'local';
            req.session.logged = true;
            return done(err, user);
        } 
        return done(err, false);
    });
};

exports.init = function (conf, app) {
    var Strategy = require('passport-local').Strategy;
    passport.use(new LocalStrategy({
        usernameField: conf.usernameField || 'email',
        passwordField: conf.passwordField || 'password',
        callbackURL: conf.baseURL + 'auth/local/callback',
        passReqToCallback: true
    }, exports.callback));

    app.post((app.settings.passportRoot || '') + '/auth/local', 
        passport.authenticate('local', {
            successRedirect: conf.redirect,
            failureRedirect: conf.redirect,
            failureFlash: conf.failureFlash
    }));
    
    app.get((app.settings.passportRoot || '') + '/auth/local/callback',
        passport.authenticate('local', { 
            failureRedirect: conf.redirect,
        }), exports.redirectOnSuccess);

};
