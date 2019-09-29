'use strict';

const https = require('https');
const express = require('express');
const fetch = require('node-fetch');
const querystring = require('querystring');
const moment = require('moment');
const url = require('url');
const crypto = require('crypto');
const crc = require('crc').crc32;
const fs = require('fs');

const KEYCLOAK_BASE_URI = 'http://localhost:8080/auth';
const KEYCLOAK_REALM = 'master';
const KEYCLOAK_USERNAME = 'admin';
const KEYCLOAK_PASSWORD = 'admin';
const SSL_ENABLED = false

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

let sessions = {};

const decodeToken = function(token) {
	return JSON.parse(Buffer.from(token.split('.')[1], 'base64'))
}

const login = async function(username, password) {
	console.log(`Logging in to '${KEYCLOAK_REALM}'...`);

	const loginData = {
		client_id: 'admin-cli',
		username,
		password,
		grant_type: 'password'
	};
	const resp = await fetch(`${KEYCLOAK_BASE_URI}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
		},
		body: querystring.encode(loginData)
	});

	let token;
	if (resp.ok)
	{
		const respData = await resp.json();

		token = respData.access_token;
		console.assert(token, "Failed to get 'access_token' from login response");
		console.log("Login successful");
	}
	else
	{
		console.error("Failed to login");
		console.error(await resp.json());
	}

	return token;
}

const getClients = async function(auth) {
	let clients = null;
	const resp = await fetch(`${KEYCLOAK_BASE_URI}/admin/realms/${KEYCLOAK_REALM}/clients`, {
		method: 'GET',
		headers: {
			Authorization: 'Bearer ' + auth
		}
	});

	if (resp.ok)
	{
		clients = await resp.json();
	}
	else
	{
		console.error(resp.status, resp.statusText);
		console.error(await resp.text());
	}

	return clients
};

const getClient = async function(auth, clientId) {
	console.log(`Finding client '${clientId}`);
	const clients = await getClients(auth);

	console.log(`Have ${clients.length} clients`);
	const client = clients.find(function(item) {
		return item.clientId === clientId;
	});

	return client;
}

const createClient = async function(auth, clientid) {
	let client = null;
	let resp = await fetch(`${KEYCLOAK_BASE_URI}/admin/realms/${KEYCLOAK_REALM}/clients`, {
		method: 'POST',
		headers: {
			Authorization: 'Bearer ' + auth,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			clientId: clientid
		})
	});

	if (resp.ok)
	{
		resp = await fetch(resp.headers.get('location'), {
			method: 'GET',
			headers: {
				Authorization: 'Bearer ' + auth
			}
		});

		if (resp.ok)
		{
			client = await resp.json();
		}
		else
		{
			console.error("Failed to get created client");
			console.error(await resp.text());
		}
	}
	else
	{
		console.error("Failed to create client");
		console.error(await resp.text());
	}

	return client;
}

const getClientSecret = async function(auth, client) {
	let secret;
	console.log(`Reteriving client secret for '${client.clientId}'`);
	const credentialResp = await fetch(`${KEYCLOAK_BASE_URI}/admin/realms/${KEYCLOAK_REALM}/clients/${client.id}/client-secret`, {
		headers: {
			Authorization: 'Bearer ' + auth
		}
	});

	if (credentialResp.ok)
	{
		const respData = await credentialResp.text();
		const credentialJson = JSON.parse(respData);
		// console.log("Reterived client secret", respData);

		if (credentialJson.value)
		{
			secret = credentialJson.value;
			console.log(`Client secret '${secret}'`);
		}
		else
		{
			console.error("Failed to get client secret");
			console.error(await credentialResp.text());
		}
	}
	else
	{
		console.error("Failed to get client secret");
		console.error(await credentialResp.text());
	}

	return secret;
}

const tokenExchange = async function(auth, clientId, code) {
	console.log(`Beginning token exchange for '${clientId}'`);

	const client = await getClient(auth, clientId);

	let tokens;
	if (client)
	{
		console.log("Found client, reteriving secret");

		const secret = await getClientSecret(auth, client);

		if (secret)
		{
			const exchangeData = {
				client_id: client.clientId,
				client_secret: secret,
				grant_type: 'authorization_code',
				code: code,
				// FIXME
				redirect_uri: 'http://localhost/index.html?client=' + clientId,
				scope: 'openid,openid-connect,offline_access'
			};

			console.log("Exchange data", exchangeData);
			const resp = await fetch(`${KEYCLOAK_BASE_URI}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
				},
				body: querystring.encode(exchangeData)
			});

			if (resp.ok)
			{
				tokens = await resp.json();

				const accessToken = decodeToken(tokens.access_token);
				const accessTokenDuration = moment.duration(moment.unix(accessToken.exp).diff(moment()));
				console.log(`Access token '${crc(tokens.access_token).toString(16)}' will expire in ${accessTokenDuration.asSeconds()}s`);

				const refreshToken = decodeToken(tokens.refresh_token);
				const refreshTokenDuration = moment.duration(moment.unix(refreshToken.exp).diff(moment()));
				console.log(`Refresh token '${crc(tokens.refresh_token).toString(16)}' will expire in ${refreshTokenDuration.asSeconds()}s`);
			}
			else
			{
				console.error("Failed to perform token exchange");
				console.error(resp.status, resp.statusText, await resp.text());
			}
		}
	}

	return tokens;
}

const refreshToken = async function(auth, refreshToken) {
	let tokens;

	const parsedToken = decodeToken(refreshToken);
	console.log(`Beginning token refresh for token ${parsedToken.azp}`);

	const client = await getClient(auth, parsedToken.azp);

	const secret = await getClientSecret(auth, client);

	const data = {
		client_id: client.clientId,
		client_secret: secret,
		grant_type: ('refresh_token'),
		refresh_token: refreshToken
	};
	const resp = await fetch(`${KEYCLOAK_BASE_URI}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`, {
		method: 'POST',
		headers: {
			Authorization: 'Bearer ' + auth,
			'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
		},
		body: querystring.encode(data)
	});

	if (resp.ok)
	{
		console.log("Refresh successful");
		tokens = await resp.json();


		const accessToken = decodeToken(tokens.access_token);
		const accessTokenDuration = moment.duration(moment.unix(accessToken.exp).diff(moment()));
		console.log(`Access token '${crc(tokens.access_token).toString(16)}' will expire in ${accessTokenDuration.asSeconds()}s`);

		const refreshToken = decodeToken(tokens.refresh_token);
		const refreshTokenDuration = moment.duration(moment.unix(refreshToken.exp).diff(moment()));
		console.log(`Refresh token '${crc(tokens.refresh_token).toString(16)}' will expire in ${refreshTokenDuration.asSeconds()}s`);
	}
	else
	{
		console.error("Failed to refresh token");
		console.error(await resp.text());
	}

	return tokens;
}

process.on('unhandledRejection', (reason, p) => {
	console.log('Unhandled Rejection: Promise', p, 'reason:', reason);
});

const app = express();
app.use(express.json());

const router = express.Router();
router.use(function(req, res, next) {
	next();
});

app.use('/node_modules', express.static('node_modules', {
	maxAge: '1d'
}));

app.use(express.static('public', {
	maxAge: '1d'
}));

app.use('/create_client', async function(req, res) {

	// create a new client on keycloak
	const clientId = req.body.clientid;
	console.assert(clientId, "Missing 'clientId' from request");
	console.log(`Attempting to create client ${clientId}`);

	let status = 500;
	try
	{
		const token = await login(KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD);

		const client = await createClient(token, clientId);
		status = 200;
	}
	catch (err)
	{
		console.error(err);
		status = 500;
	}

	res.sendStatus(status);
});

app.use('/clients', async function(req, res) {
	let status = 500;
	let clients = {};
	try
	{
		const token = await login(KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD);

		clients = await getClients(token);
		status = 200;
	}
	catch (err)
	{
		console.error(err);
		status = 500;
	}

	res.send(clients);
});

app.use('/exchange', async function(req, res) {
	const code = req.body.code;
	const client = req.body.client;
	const sessionState = req.body.sessionState;
	const instance = req.query.instance;

	console.assert(code, `Missing 'code' from request body`);
	console.assert(client, `Missing 'client' from request body`);
	console.assert(instance, `Missing 'instance' from request`);

	let tokens;
	try
	{
		const auth = await login(KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD);
		tokens = await tokenExchange(auth, client, code);

		if (tokens)
		{
			sessions[instance] = tokens;

			console.log(`Sessioan started for '${instance}' '${crc(tokens.refresh_token).toString(16)}'`);
		}
	}
	catch (err)
	{
		console.error(err);
	}

	if (tokens && tokens.access_token)
	{
		res.send({ access_token: tokens.access_token });
	}
	else
	{
		res.sendStatus(500);
	}
});

app.use('/token', function(req, res) {
	let token;

	const instance = req.query.instance;
	console.assert(instance, `Missing 'instance' from request`);

	if (sessions[instance])
	{
		res.send({ access_token: sessions[instance].access_token });
	}
	else
	{
		console.log(`Could not find session '${instance}'`);
		res.clearCookie('session');
		res.sendStatus(401);
	}
});

app.put('/refresh', async function(req, res) {

	const instance = req.query.instance;
	console.assert(instance, `Missing 'instance' from request`);

	if (sessions[instance])
	{
		try
		{
			const auth = await login(KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD);
			const tokens = await refreshToken(auth, sessions[instance].refresh_token);

			if (tokens)
			{
				console.log(`Got new refresh token for '${instance}' '${crc(tokens.refresh_token).toString(16)}'`);
				sessions[instance] = tokens;
				res.sendStatus(204);
			}
			else
			{
				console.error("Failed to refresh token");
				res.sendStatus(400);
			}
		}
		catch (err)
		{
			console.error("Failed to refresh token");
			console.error(err);
			res.sendStatus(400);
		}
	}
	else
	{
		console.error(`Could not find session '${instance}'`);
		res.clearCookie('session');
		res.sendStatus(401);
	}
});

try
{
	if (SSL_ENABLED)
	{
		https.createServer({
			key: fs.readFileSync('server.key'),
			cert: fs.readFileSync('server.cert')
		}, app).listen(443, () => { console.log("Listening..."); });
	}
	else
	{
		app.listen(80, () => console.log("Listening..."));
	}
}
catch (err)
{
	console.error("Failed to start Express", err);
}

