export default class Utils{
	static env;
	static date;
	static IP;
	static hashedIP;
	static cache = caches.default;

	static async initialize(env, ip){
		this.env = env;
		this.date = new Date().toISOString();
		this.IP = ip;
		this.hashedIP = await this.generateHash('rabbitcompany-' + ip + this.date.split('T')[0], 'SHA-256');
	}

	static jsonResponse(json, statusCode = 200){
		if(typeof(json) !== 'string') json = JSON.stringify(json);
		return new Response(json, {
			headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
			status: statusCode
		});
	}

	static async generateHash(message, hash = 'SHA-512'){
		const msgUint8 = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest(hash, msgUint8);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
	}

	static basicAuthentication(authorization) {
		if(authorization === null) return null;
		const [scheme, encoded] = authorization.split(' ');
		if (!encoded || scheme !== 'Basic') return null;
		const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
		const decoded = new TextDecoder().decode(buffer).normalize();

		const index = decoded.indexOf(':');
		if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) return null;

		return { user: decoded.substring(0, index), pass: decoded.substring(index + 1) };
	}

	static async setValue(key, value, expirationTime = null, cacheTime = 60){
		let cacheKey = "https://api.rabbitemail.org?key=" + key;
		if(expirationTime === null){
			await this.env.KV.put(key, value);
		}else{
			await this.env.KV.put(key, value, { expirationTtl: expirationTime });
		}
		let nres = new Response(value);
		nres.headers.append('Cache-Control', 's-maxage=' + cacheTime);
		await this.cache.put(cacheKey, nres);
	}

	static async getValue(key, cacheTime = 60){
		let value = null;

		let cacheKey = "https://api.rabbitemail.org?key=" + key;
		let res = await this.cache.match(cacheKey);
		if(res) value = await res.text();

		if(value == null){
			value = await this.env.KV.get(key, { cacheTtl: cacheTime });
			let nres = new Response(value);
			nres.headers.append('Cache-Control', 's-maxage=' + cacheTime);
			if(value != null) await this.cache.put(cacheKey, nres);
		}

		return value;
	}

	static async deleteValue(key){
		await this.env.KV.delete(key);
		await this.cache.delete("https://api.rabbitemail.org?key=" + key);
	}
}