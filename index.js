var http 		= require('http'),
	querystring = require('querystring'),
	MethodTable = (JSON.parse(require('fs').readFileSync(__dirname + '/methods.json'))).results;

// Create Servant Class-based Object
function Servant(client_id, client_secret, redirect_uri, api_version) {
	// Check Formats of Parameters submitted
	if(typeof api_key == 'string') {
		this._api_key = client_id;
	} else {
		this._api_key = null;
	}

	// TO DO - VALIDATIONS For this and API_VERSION
	this._redirect_uri = redirect_uri;

	// Initialize the OAuth2 Library
	var OAuth2 = require('simple-oauth2')({
	    clientID:           client_id,
	    clientSecret:       client_secret,
	    authorizationPath:  '/oauth/authorize',
	    tokenPath:          '/oauth/token',
	    site:               'http://www.servant.co'
	});
	// Servant Authentication Methods
	this.authorization_uri = OAuth2.AuthCode.authorizeURL({
		  redirect_uri: redirect_uri
	});

	console.log(this.authorization_uri)

	this.getAccessToken = function(req, callback) {
		console.log("here!!!!");
		// Get the access token object (the authorization code is given from the previous step).
		var code = req.query.code
		var token;
		OAuth2.AuthCode.getToken({
		  code:           code,
		  redirect_uri:   redirect_uri
		}, saveToken);

		// Save the access token
		function saveToken(error, result) {
		  if (error) { console.log('Access Token Error', error.message) }
		  token = OAuth2.AccessToken.create(result);
		  console.log("TOKEN CREATED: ", token)
		};
	};

	if(!Servant.prototype.methodsLoaded) {
		for(var i = 0; i < MethodTable.length; ++i) {
			var method = MethodTable[i];

			Servant.prototype[method.name] = Servant.prototype._createMethod(
				method.http_method,
				method.uri,
				method.visibility,
				method.params
			);
		}

		Servant.prototype.methodsLoaded = true;
	}
}

Servant.prototype.methodsLoaded = false;

// Creates An API Method for each Method listed in Methods.json
Servant.prototype._createMethod = function(http_method, uri, visibility, param_types) {
	if(typeof http_method == 'undefined')
	{
		throw new Error('missing required argument http_method');
	}

	if(typeof uri == 'undefined')
	{
		throw new Error('missing required argument uri');
	}

	if(typeof visibility == 'undefined')
	{
		throw new Error('missing required argument visibility');
	}

	if(typeof param_types == 'undefined')
	{
		throw new Error('missing required argument param_types');
	}

	if(http_method != 'GET' && http_method != 'POST' && http_method != 'PUT' && http_method != 'DELETE')
	{
		throw new Error('invalid HTTP method "' + http_method + '"');
	}

	if(typeof uri != 'string')
	{
		throw new Error('URI is not a string');
	}

	if(visibility != 'public' && visibility != 'private')
	{
		throw new Error('method visibility is neither public nor private');
	}

	return function(params, token, callback) {
		if(typeof token == 'function')
		{
			if(typeof callback == 'undefined')
			{
				callback = token;

				if(params instanceof oauth.Token)
				{
					token = params;
					params = null;
				}
				else if(typeof params == 'object')
				{
					token = null;
				}
			}
		}

		// copy the visibility so it can be safely modified
		var vis = visibility;

		if(vis == 'public')
		{
			if(token)
			{
				// if a token is passed in, make the call private
				vis = 'private';
			}
		}
		else if(vis == 'private')
		{
			if(!token)
			{
				return callback(new Error("no token provided for private method"));
			}
		}

		this._callAPI(
			http_method, // HTTP method
			uri, // URI
			vis, // visibility
			param_types, // parameter types
			params, // parameters
			token, // OAuth access token and secret
			callback); // callback for call completion
	};
};

// Parses URI and separates Params and other useful things
Servant.prototype._formatURI = function(uri, visibility, params) {
	var uri_builder = [this._call_base, '/', visibility];
	var idx = 0, cidx = 0;

	do
	{
		// search for a URI param marker
		cidx = uri.indexOf(':', idx);

		// couldn't find any more URI parameters
		if(cidx == -1)
		{
			// append the rest of the URI; we're done
			uri_builder.push(uri.substr(idx));
			break;
		}

		// append URI part between the last known delimiter and param
		uri_builder.push(uri.substring(idx, cidx));

		// find next delimiter
		idx = uri.indexOf('/', cidx);

		if(idx == -1) // no more delimiters; we're done
		{
			param_name = uri.substr(cidx + 1);
		}
		else
		{
			param_name = uri.substring(cidx + 1, idx);
		}

		if(param_name in params)
		{
			uri_builder.push(querystring.escape(params[param_name]));
			delete params[param_name];
		}
		else
		{
			throw new Error('missing required parameter "' +
			param_name + '" in request parameters');
		}
	} while(idx != -1);

	return uri_builder.join('');
};

// Calls the API's resources
Servant.prototype._callAPI = function(http_method, uri, visibility, param_types, params, token, callback)
{
	var new_params = {}, param_name;
	for(param_name in params)
	{
		if(params.hasOwnProperty(param_name))
		{
			if(param_name == 'fields')
			{
				if(!this._checkType(params[param_name], 'array(string)', visibility))
				{
					return callback(new TypeError('fields is not an array of strings'));
				}
			}
			else if(param_name == 'includes')
			{
				if(!this._checkType(params[param_name], 'array(string)', visibility))
				{
					return callback(new TypeError('includes is not an array of strings'));
				}

				var includes = params[param_name];

				// regex for matching associations: the second half is just the
				// first one wrapped in parens with an extra slash in front
				// and an asterisk after, for nested associations
				var assoc_regex = /^[A-Za-z]+(\(([a-z0-9_]+,)*[a-z0-9_]+\))?(:[A-Za-z]+)?(:[0-9]+(:[0-9]+)?)?(\/[A-Za-z]+(\(([a-z0-9_]+,)*[a-z0-9_]+\))?(:[A-Za-z]+)?(:[0-9]+(:[0-9]+)?)?)*$/;

				if(includes instanceof Array)
				{
					for(var i = 0; i < includes.length; ++i)
					{
						if(!assoc_regex.test(includes[i]))
						{
							return callback(new TypeError('association ' + i + ' is malformatted'));
						}
					}
				}
				else
				{
					if(!assoc_regex.test(includes))
					{
						return callback(new TypeError('association 0 is malformatted'));
					}
				}
			}
			else
			{
				if(!(param_name in param_types))
				{
					return callback(new TypeError('"' + param_name +
					'" is not a valid parameter for this request'));
				}

				if(!this._checkType(params[param_name], param_types[param_name], visibility))
				{
					callback(new TypeError('"' + params[param_name] + 
					'" does not match the parameter description "' +
					param_types[param_name] + '"'));
					return;
				}
			}

			if(params[param_name] instanceof Array)
			{
				new_params[param_name] = params[param_name].join(',');
			}
			else
			{
				new_params[param_name] = params[param_name];
			}
		}
	}

	if(token === null)
	{
		new_params.api_key = this._api_key;
	}

	var headers = {
		'Connection' : 'Keep-Alive',
		'Host': 'openapi.etsy.com'
	};

	var request_url = '';

	try
	{
		request_url = this._formatURI(uri, visibility, new_params);
	} catch(e) {
		return callback(e);
	}

	if(http_method == 'GET')
	{
		request_url += '?' + querystring.stringify(new_params);
		headers['Content-Length'] = 0;
	}

	var request;

	if(token === null)
	{
		request = http.Client.prototype.request.call(
			this._client,
			http_method,
			request_url,
			headers
		);

		request.end(http_method == 'GET' ? null : querystring.stringify(new_params));
	}
	else
	{
		this._signature.token = token;

		request = this._client.request(
			http_method,
			request_url,
			headers,
			http_method == 'GET' ? null : new_params,
			this._signature
		);
		request.end();

		this._signature.token = null;
	}

	request.on('response', function(response) {
		response.setEncoding('utf8');
		var data = '';
		var err = null;

		switch(response.statusCode)
		{
			case 200:
			case 201:
			response.on('data', function(chunk) { data += chunk; });
			response.on('end', function() {
				callback(null, JSON.parse(data));
			});
			return;

			case 400:
			err = new Error('API call request is malformatted');
			break;

			case 401:
			err = new Error('API call request is unauthorized');
			break;

			case 403:
			err = new Error('requested resource is not available');
			break;

			case 404:
			err = new Error('requested resource could not be found');
			break;

			case 409:
			err = new Error('requested resource is currently locked and cannot be modified');
			break;

			case 500:
			err = new Error('an error occurred in Servant API while processing the request');
			break;

			case 504:
			err = new Error('the API timed out while processing the request');
			break;
		}

		if(!err)
		{
			err = new Error('API call failed due to unknown error');
		}

		err.statusCode = response.statusCode;
		err.errorCode = response.headers['x-mashery-error-code'] || null;
		err.url = request_url;
		callback(err);

	});
};

// Check if API Call Is Only Reading or Reading & Writing
Servant.prototype._checkType = function(value, param_type, visibility)
{
	if(typeof visibility == 'undefined')
	{
		visibility = 'public';
	}

	if(param_type.indexOf('array(') === 0 && param_type[param_type.length - 1] == ')')
	{
		param_type = param_type.substring('array('.length, param_type.length - 1);

		if(value instanceof Array)
		{
			for(var i = 0; i < value.length; i++)
			{
				if(!this._checkType(value[i], param_type))
				{
					return false;
				}
			}

			return true;
		}
		else
		{
			return this._checkType(value, param_type);
		}
	}

	if(param_type.indexOf('enum(') === 0 && param_type[param_type.length - 1] == ')')
	{
		var enums = param_type.substring('enum('.length, param_type.length - 1).split(',');

		for(var i = 0; i < enums.length; i++)
		{
			enums[i] = enums[i].trim();
		}

		if(enums.indexOf(value.toString()) == -1)
		{
			return false;
		}

		return true;
	}

	switch(param_type)
	{
		case 'int':
		if(isNaN(value) || (parseFloat(value) != parseInt(value, 10)))
		{
			return false;
		}
		break;

		case 'float':
		if(!isFinite(value))
		{
			return false;
		}
		break;

		case 'string':
		if(
			!value.toString ||
			value.toString == Object.prototype.toString ||
			value.toString == Function.prototype.toString ||
			value.toString == RegExp.prototype.toString)
		{
			return false;
		}

		if(value.toString().length > 255)
		{
			return false;
		}
		break;

		case 'user_id_or_name':
		if(value == '__SELF__')
		{
			return true;
		}

		// fallthrough

		case 'shop_id_or_name':
		if(!this._checkType(value, 'int'))
		{
			if(this._checkType(value, 'string') && !/^[A-Za-z][A-Za-z0-9]{2,19}$/.test(value.toString()))
			{
				return false;
			}
		}
		break;

		case 'color_triplet':
		var hsv = [];

		if(value instanceof Array)
		{
			hsv = value;
		}
		else
		{
			hsv = value.split(',');
		}

		if(hsv.length == 3)
		{
			if(
				(hsv[0] >= 0 && hsv[0] <= 360) ||
				(hsv[1] >= 0 && hsv[1] <= 100) ||
				(hsv[2] >= 0 && hsv[2] <= 100))
			{
				return true;
			}
		}

		if(/^#?([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(value))
		{
			return true;
		}

		return false;

		case 'color_wiggle':
		return (value >= 0 && value <= 30);

		default:
		return false;
	}

	return true;
};

exports.Servant = Servant;