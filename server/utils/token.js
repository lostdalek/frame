'use strict';
const AuthPlugin = require('../auth');
const jwt = require('jsonwebtoken');
const Config = require('../../config');

function createToken(user, session) {
    let scopes;

    // scopes to admin
    if (AuthPlugin.preware.ensureAdminGroup('root')) {
        scopes = 'admin';
    }
    // Sign the JWT
    return jwt.sign({
        id: user._id,
        username: user.username,
        sessionId: session._id.toString(),
        sessionKey: session.key,
        scope: scopes }, Config.get('/jwtSecret'), { algorithm: 'HS256', expiresIn: "1h" } );
}

module.exports = createToken;