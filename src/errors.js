export default class Errors{

	static list = {
		0: 'Success',
		1000: 'Not all required data provided in json format.',
		1001: 'Username can only contain lowercase characters, numbers and hyphens. It also needs to start with lowercase character and be between 4 and 30 characters long.',
		1002: 'Invalid email address.',
		1003: 'Password needs to be hashed with Blake2b. The length of hashed password needs to be 128 characters.',
		1004: 'Token is invalid. Please login first to get the token.',
		1005: 'Username is already registered.',
		1006: 'Basic Authentication is missing.',
		1007: 'Password is incorrect.',
		1008: 'The token is incorrect or it has expired. Please Sign in again.',
		1009: 'Something went wrong while trying to perform this action. Please try again later.',
		1034: 'Captcha is invalid.',
		9999: 'Your do not have permission to perform this action.'
	};

	static get(id){
		return this.list[id];
	}

	static getJson(id){
		return { 'error': id, 'info': this.list[id] };
	}

}