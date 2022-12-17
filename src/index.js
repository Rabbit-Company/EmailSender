function basicAuthentication(request) {
  const Authorization = request.headers.get('Authorization');
  const [scheme, encoded] = Authorization.split(' ');
  if(!encoded || scheme !== 'Basic'){
    return new Response('Credentials are invalid!', { status: 401 });
  }

  const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
  const decoded = new TextDecoder().decode(buffer).normalize();

  const index = decoded.indexOf(':');
  if(index === -1 || /[\0-\x1F\x7F]/.test(decoded)){
		return new Response('Credentials are invalid!', { status: 401 });
  }

  return{
    user: decoded.substring(0, index),
    pass: decoded.substring(index + 1),
  };
}

export default {
	async fetch(request, env, ctx) {
		const { headers } = request;
		const contentType = headers.get('content-type') || '';
		
		if(!headers.has('Authorization')){
			return new Response('Authentication is required!', { status: 401 });
		}

		const { user, pass } = basicAuthentication(request);
		if(user !== env.USER || pass != env.PASSWORD){
			return new Response('Credentials are invalid!', { status: 401 });
		}

		if(!contentType.includes('form')){
			return new Response('Data needs to be submitted in POST!', { status: 400 });
		}

    const formData = await request.formData();
    const data = {};
    for (const entry of formData.entries()) data[entry[0]] = entry[1];
		const receiver = data['receiver'];
		const subject = data['subject'];
		const message = data['message'];

		if(!(/\S+@\S+\.\S+/.test(receiver))){
			return new Response('Receiver is invalid!', { status: 400 });
		}

		if(typeof(subject) !== 'string' || subject == null || subject.length < 1 || subject.length > 255){
			return new Response('Subject is invalid!', { status: 400 });
		}

		if(typeof(message) !== 'string' || message == null || message.length < 1 || message.length > 100000){
			return new Response('Message is invalid!', { status: 400 });
		}

		const response = await fetch('https://api.mailchannels.net/tx/v1/send', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        personalizations: [
          {
            to: [{ email: receiver }],
						dkim_domain: env.DKIM_DOMAIN,
						dkim_selector: env.DKIM_SELECTOR,
						dkim_private_key: env.DKIM_PRIVATE_KEY
          },
        ],
        from: {
          email: env.EMAIL,
          name: env.NAME,
        },
        subject: subject,
        content: [
          {
            type: 'text/html',
            value: message,
          },
        ],
      }),
    });

		if(!response.ok || (response.status != 200 && response.status != 202)){
			return new Response(response.statusText, { status: response.status });
		}

		return new Response('{"status":"success"}', { status: 200 });
	},
};