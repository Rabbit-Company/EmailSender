export default class Validate{

	static username(username){
		if(typeof(username) !== 'string') return false;
		return /^([a-z][a-z0-9\-]{3,29})$/.test(username);
	}

	static password(password){
		if(typeof(password) !== 'string') return false;
		return /^([a-z0-9]{128})$/.test(password);
	}

	static email(email){
		if(typeof(email) !== 'string') return false;
		return /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(email);
	}

	static token(token){
		if(typeof(token) !== 'string') return false;
		return token.length === 128;
	}

	static captcha(captcha){
		if(typeof(captcha) !== 'string') return false;
		return /^([a-zA-Z0-9._\-]{200,2048})$/.test(captcha);
	}
}