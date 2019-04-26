module.exports = function (RED) {

    const url = require('url');
    const crypto = require('crypto');
    const SpotifyWebApi = require('spotify-web-api-node');

    // When our access token will expire
    var tokenExpirationEpoch;

    function AuthNode(config) {
        RED.nodes.createNode(this, config);

        this.name = config.name;
        this.scope = config.scope;
    }
    RED.nodes.registerType("spotify-auth", AuthNode, {
        credentials: {
            name: { type: 'text' },
            clientId: { type: 'password' },
            clientSecret: { type: 'password' },
            accessToken: { type: 'password' },
            refreshToken: { type: 'password' },
            expireTime: { type: 'password' }
        }
    });

    RED.httpAdmin.get('/spotify-credentials/auth', function (req, res) {
        if (!req.query.clientId || !req.query.clientSecret ||
            !req.query.id || !req.query.callback) {
            res.send(400);
            return;
        }

        const node_id = req.query.id;
        const credentials = {
            clientId: req.query.clientId,
            clientSecret: req.query.clientSecret,
            callback: req.query.callback
        };
        const scope = req.query.scope;
        const csrfToken = crypto.randomBytes(18).toString('base64').replace(/\//g, '-').replace(/\+/g, '_');
        credentials.csrfToken = csrfToken;

        res.redirect(url.format({
            protocol: 'https',
            hostname: 'accounts.spotify.com',
            pathname: '/authorize',
            query: {
                client_id: credentials.clientId,
                response_type: 'code',
                redirect_uri: credentials.callback,
                state: node_id + ':' + csrfToken,
                show_dialog: true,
                scope: scope
            }
        }));
        RED.nodes.addCredentials(node_id, credentials);
    });

    RED.httpAdmin.get('/spotify-credentials/auth/callback', function (req, res) {
        if (req.query.error) {
            return res.send('spotify.query.error', { error: req.query.error, description: req.query.error_description });
        }

        const state = req.query.state.split(':');
        const node_id = state[0];
        const credentials = RED.nodes.getCredentials(node_id);

        if (!credentials || !credentials.clientId || !credentials.clientSecret) {
            return res.send('spotify.error.no-credentials');
        }
        if (state[1] !== credentials.csrfToken) {
            return res.send('spotify.error.token-mismatch');
        }

        const spotifyApi = new SpotifyWebApi({
            clientId: credentials.clientId,
            clientSecret: credentials.clientSecret,
            redirectUri: credentials.callback
        });

        spotifyApi.authorizationCodeGrant(req.query.code).then(data => {
            credentials.accessToken = data.body.access_token;
            credentials.refreshToken = data.body.refresh_token;
            credentials.expireTime = data.body.expires_in;
            credentials.tokenType = data.body.token_type;
            credentials.name = 'Spotify OAuth2';

            // Set the access token and refresh token
            spotifyApi.setAccessToken(data.body['access_token']);
            spotifyApi.setRefreshToken(data.body['refresh_token']);

            // Save the amount of seconds until the access token expired
            tokenExpirationEpoch = new Date().getTime() / 1000 + data.body['expires_in'];
            console.log(
                'Retrieved token. It expires in ' +
                Math.floor(tokenExpirationEpoch - new Date().getTime() / 1000) +
                ' seconds!'
            );

            delete credentials.csrfToken;
            delete credentials.callback;
            RED.nodes.addCredentials(node_id, credentials);
            res.send('spotify.authorized');
        })
        .catch(error => {
            res.send('spotify.error.tokens');
        });
    });

    // Check for token renewal every minute
    setInterval(function() {
        if (tokenExpirationEpoch == null || tokenExpirationEpoch == 0) {
            console.log('tokenExpirationEpoch was not set. Skipping token renewal.');
            return;
        }
        var secondsLeft = Math.floor(tokenExpirationEpoch - new Date().getTime() / 1000);
        console.log(
          'Token renewal time left: ' + secondsLeft + ' seconds left!'
        );
      
        // OK, we need to refresh the token. Stop printing and refresh.
        if (secondsLeft < (60 * 5)) {
          clearInterval(this);
      
          // Refresh token and print the new time to expiration.
          spotifyApi.refreshAccessToken().then(
            function(data) {
              tokenExpirationEpoch =
                new Date().getTime() / 1000 + data.body['expires_in'];
              console.log(
                'Refreshed token. It now expires in ' + Math.floor(tokenExpirationEpoch - new Date().getTime() / 1000) + ' seconds!'
              );
            },
            function(err) {
              console.log('Could not refresh the token!', err.message);
            }
          );
        }
    }, 60000);
};