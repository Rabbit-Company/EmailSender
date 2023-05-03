import Utils from "./utils.js";
import Validate from "./validate.js";
import Errors from "./errors.js";

export default class Account{

	static async create(username, email, password, turnstile){
		if(!Validate.username(username)) return Errors.getJson(1001);
		if(!Validate.email(email)) return Errors.getJson(1002);
		if(!Validate.password(password)) return Errors.getJson(1003);
		if(!Validate.captcha(turnstile)) return Errors.getJson(1034);

		let formData = new FormData();
		formData.append('secret', Utils.env.CF_TURNSTILE_TOKEN);
		formData.append('response', turnstile);
		formData.append('remoteip', Utils.IP);

		const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
		const result = await fetch(url, { body: formData, method: 'POST' });
		const outcome = await result.json();
		if(!outcome.success) return Errors.getJson(1034);

		password = await Utils.generateHash('rabbitemailsender-' + username + '-' + password);
		try{
			await Utils.env.DB.prepare("INSERT INTO accounts(username, password, email, created, accessed) VALUES(?, ?, ?, ?, ?)").bind(username, password, email, Utils.date, Utils.date).run();
		}catch{
			return Errors.getJson(1005);
		}

		return Errors.getJson(0);
	}

	static async token(username, password){
		if(!Validate.username(username)) return Errors.getJson(1001);
		if(!Validate.password(password)) return Errors.getJson(1003);

		password = await Utils.generateHash('rabbitemailsender-' + username + '-' + password);
		try{
			let { results } = await Utils.env.DB.prepare("SELECT * FROM accounts WHERE username = ? AND password = ?").bind(username, password).all();
			if(results.length !== 1) return Errors.getJson(1007);
		}catch{
			return Errors.getJson(1005);
		}

		let token = await Utils.generateToken(username);
		let message = Errors.getJson(0);
		message['token'] = token;
		return message;
	}

}