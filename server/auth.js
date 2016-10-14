'use strict';
const Async = require('async');
const Boom = require('boom');
const Config = require('../config');

const internals = {};


internals.applyStrategy = function (server, next) {

    const Session = server.plugins['hapi-mongo-models'].Session;
    const User = server.plugins['hapi-mongo-models'].User;

    server.auth.strategy('simple', 'basic', {
        validateFunc: function (request, username, password, callback) {

            Async.auto({
                session: function (done) {
                    Session.findByCredentials(username, password, done);
                },
                user: ['session', function (results, done) {

                    if (!results.session) {
                        return done();
                    }

                    User.findById(results.session.userId, done);
                }],
                roles: ['user', function (results, done) {

                    if (!results.user) {
                        return done();
                    }

                    results.user.hydrateRoles(done);
                }],
                scope: ['user', function (results, done) {

                    if (!results.user || !results.user.roles) {
                        return done();
                    }

                    done(null, Object.keys(results.user.roles));
                }]
            }, (err, results) => {

                if (err) {
                    return callback(err);
                }

                if (!results.session) {
                    return callback(null, false);
                }

                callback(null, Boolean(results.user), results);
            });
        }
    });


    next();
};


internals.applyJwtStrategy = function (server, next) {
    const Session = server.plugins['hapi-mongo-models'].Session;
    const User = server.plugins['hapi-mongo-models'].User;


    server.auth.strategy('jwt', 'jwt', {
        key: Config.get('/jwtSecret'),
        verifyOptions: { algorithms: ['HS256'] },

        validateFunc: function (decodedToken, request, callback) {

            Async.auto({
                session: function (done) {
                    Session.findByCredentials(decodedToken.sessionId, decodedToken.sessionKey, done);
                },
                user: ['session', function (results, done) {

                    if (!results.session) {
                        return done();
                    }

                    User.findById(results.session.userId, done);
                }],
                roles: ['user', function (results, done) {

                    if (!results.user) {
                        return done();
                    }

                    results.user.hydrateRoles(done);
                }],
                scope: ['user', function (results, done) {

                    if (!results.user || !results.user.roles) {
                        return done();
                    }

                    done(null, Object.keys(results.user.roles));
                }]
            }, (err, results) => {

                if (err) {
                    return callback(err);
                }

                if (!results.session) {
                    return callback(null, false);
                }

                callback(null, Boolean(results.user), results);
            });
        }
    });


    next();
};

internals.preware = {
    ensureNotRoot: {
        assign: 'ensureNotRoot',
        method: function (request, reply) {

            if (request.auth.credentials.user.username === 'root') {
                const message = 'Not permitted for root user.';

                return reply(Boom.badRequest(message));
            }

            reply();
        }
    },
    ensureAdminGroup: function (groups) {

        return {
            assign: 'ensureAdminGroup',
            method: function (request, reply) {

                if (Object.prototype.toString.call(groups) !== '[object Array]') {
                    groups = [groups];
                }

                const groupFound = groups.some((group) => {

                    return request.auth.credentials.roles.admin.isMemberOf(group);
                });

                if (!groupFound) {
                    return reply(Boom.notFound('Permission denied to this resource.'));
                }

                reply();
            }
        };
    }
};


exports.register = function (server, options, next) {

    if( Config.get('/authStrategy') === 'simple') {
        server.dependency('hapi-mongo-models', internals.applyStrategy);
    } else {
        server.dependency(['hapi-mongo-models', 'hapi-auth-jwt2'], internals.applyJwtStrategy);
    }

    next();
};


exports.preware = internals.preware;


exports.register.attributes = {
    name: 'auth'
};
