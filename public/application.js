'use strict';

const KEYCLOAK_BASE_URI = 'http://localhost:8080/auth';
const KEYCLOAK_REALM = 'master';
let instance = null;

const Logger = (function(el) {
	return function(msg, options) {
		options = options || {};
		const d = moment();

		let p = document.createElement('p');

		options.level = options.level || 'information';
		p.classList.add(options.level);

		p.innerHTML = `<span class="datestamp">${d.format('HH:mm:ss.S')}</span>${msg}`;
		el.prepend(p);

		console.log(`${d.format('HH:mm:ss.S')} ${msg}`);
	}
});

let log;

const index = async function() {
	const el = document.getElementById('content');

	const resp = await fetch('/clients');

	if (resp.ok)
	{
		const json = await resp.json();

		let added = false
		json.forEach(function(item) {
			if (['master-realm', 'account', 'admin-cli', 'security-admin-console', 'broker'].includes(item.clientId) === false)
			{
				// console.log(item);
				let itemEl = document.createElement('div');
				itemEl.classList.add('client');
				itemEl.innerHTML = `<span>${item.clientId}</span> <button type="button" data-control="login" name="${item.clientId}">Login</button>`;
				el.append(itemEl);

				added = true;
			}
		});

		if (!added)
		{
			let itemEl = document.createElement('div');
			itemEl.classList.add('client');
			itemEl.innerHTML = 'No user clients available';
			el.append(itemEl);
		}

		const btns = document.querySelectorAll('[data-control=login]');
		btns.forEach(function(btn) {
			btn.addEventListener('click', function(ev) {
				const clientId = ev.currentTarget.name;
				// FIXME
				const redirectUrl = encodeURIComponent(`${window.location.href}?client=${clientId}`);
				window.location = `${KEYCLOAK_BASE_URI}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth?client_id=${clientId}&redirect_uri=${redirectUrl}&response_type=code&scope=openid+offline_access`;
			});
		});
	}
}

const loggedin = async function() {
	let ok = false;
	const resp = await fetch('/token?instance=' + instance);
	if (resp.ok)
	{
		const json = await resp.json();

		ok = !!json.access_token;
	}
	return ok;
}

const status = async function() {
	const el = document.getElementById('content');
	el.innerHTML = ''; // may cause leaks...

	const resp = await fetch('/token?instance=' + instance);
	if (resp.ok)
	{
		const json = await resp.json();

		log(`Reterived access token for current session`);

		const parts = json.access_token.split('.');
		const decodedToken = JSON.parse(atob(parts[1]));
		const exp = moment.unix(decodedToken.exp);

		const label = document.createElement('div');
		// label.classList.add('');
		label.innerHTML = `Token Life-time`;
		el.append(label);

		// const duration = moment.duration(exp.diff(moment()));
		const tokenExp = document.createElement('div');
		tokenExp.classList.add('token-expiry');
		// tokenExp.innerHTML = `${duration.asSeconds()}`;
		el.append(tokenExp);

		let timer;
		let notified;
		const update = function() {
			const duration = moment.duration(exp.diff(moment()));
			const seconds = Math.ceil(duration.asSeconds());

			if (seconds < 10 && seconds > 0 && !notified)
			{
				log(`Token will expire in less than ten seconds`);
				notified = true;
			}

			if (seconds > 0)
			{
				tokenExp.innerHTML = `${seconds}s`;
				timer = setTimeout(update, 250);
			}
			else
			{
				tokenExp.classList.add('expired');
				tokenExp.innerHTML = `Expired`;

				if (timer)
				{
					clearTimeout(timer)
				}
			}
		}

		update();

		const btnContainer = document.createElement('div');
		// btnContainer.classList.add('');

		const btn = document.createElement('button');
		btn.setAttribute('type', 'button');
		btn.setAttribute('data-control', 'refresh');
		btn.innerHTML = 'Refresh Now';
		// btn.classList.add('');

		btnContainer.append(btn);
		el.append(btnContainer);

		btn.addEventListener('click', async function() {
			log(`Refreshing access token`);
			const resp = await fetch('/refresh?instance=' + instance, {
				method: 'PUT'
			});

			if (resp.ok)
			{
				if (timer)
				{
					clearTimeout(timer)
				}

				log(`Access token refeshed successfully!`);
				status();
			}
			else
			{
				log(`Failed to refresh access token!`, { level: 'error' });
			};
		});
	}
}

document.addEventListener('DOMContentLoaded', async function() {
	log = new Logger(document.getElementById('logcontent'));

	const parsedUrl = new URL(window.location.href);
	const exchangeCode = parsedUrl.searchParams.get('code');
	const clientId = parsedUrl.searchParams.get('client');
	const sessionState = parsedUrl.searchParams.get('session_state');

	instance = window.sessionStorage.getItem('instance');
	if (!instance)
	{
		instance = Math.floor(Math.random() * 100000).toString(16);
		window.sessionStorage.setItem('instance', instance);
	}

	log(`Client instance '${instance}'`);

	if (exchangeCode)
	{
		log(`Received token exchange code for '${clientId}', performing token exchange`);

		const exchangeResp = await fetch('/exchange?instance=' + instance, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({
				code: exchangeCode,
				client: clientId,
				sessionState: sessionState
			})
		});

		if (exchangeResp.ok)
		{
			log(`Token exchange completed`);
			window.location = '/index.html';
		}
		else
		{
			log(`Failed to exchange code for token`, { level: 'error' });
		}
	}
	else
	{
		const ok = await loggedin();
		if (ok)
		{
			status();
		}
		else
		{
			index();
		}
	}
});