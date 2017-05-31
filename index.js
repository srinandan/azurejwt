'use strict';
/**
 *
 */

var debug = require('debug')('plugin:azurejwt');
var jws = require('jws');
var request = require('request');
var rs = require('jsrsasign');
var JWS = rs.jws.JWS;

const authHeaderRegex = /Bearer (.+)/;
var acceptField = {};
acceptField.alg = ['RS256'];

const acceptAlg = ['RS256'];

module.exports.init = function (config, logger, stats) {

	var publickeys = {};
	var publickey_url = config.publickey_url;
	var client_id = config.client_id;
	var iss = config.iss;
	var exp = config.exp;

	if (iss) {
		debug("Issuer " + iss);
		acceptField.iss = [];
		acceptField.iss[0] = iss;
	}

	request({
	      url: publickey_url,
	      method: 'GET'
	    }, function (err, response, body) {
	      if (err) {
	        debug('publickey gateway timeout');
	        console.log(err);
	      } else {
	      	debug("loaded public keys");
	      	publickeys = JSON.parse(body);
	      }
		}
	);

	function getJWK(kid) {
		for (var i = 0; i < publickeys.keys.length; i ++) {
			if (publickeys.keys[i].kid == kid) {
				return publickeys.keys[i];
			}
		}
		return "";
	}

	return {
		onrequest: function(req, res, next) {
			debug('plugin onrequest');
			try {
				var jwtpayload = authHeaderRegex.exec(req.headers['authorization']);
				var isValid = false;
				if (jwtpayload) {
					var jwtdecode = jws.decode(jwtpayload[1]);
					var kid = jwtdecode.header.kid;
					if (!kid) {
						debug ("ERROR - JWT Token Missing in Auth hoeader");
					} else {
						var jwk = getJWK(kid);
						if (!jwk) {
							debug("ERROR - Could not find public key to match kid");
						} else {
							var publickey = rs.KEYUTIL.getKey(jwk);
							var pem = rs.KEYUTIL.getPEM(publickey);	
							if (exp) {
								debug("JWT Expiry enabled");
								acceptField.verifyAt = rs.KJUR.jws.IntDate.getNow();
								isValid = rs.jws.JWS.verifyJWT(jwtpayload[1], pem, acceptField);
							} else {
								debug("JWT Expiry disabled");
								isValid = rs.jws.JWS.verify(jwtpayload[1], pem, acceptAlg);
							}	
							if(isValid) {
								delete (req.headers['authorization']);//removing the azure header
								req.headers['x-api-key'] = jwtdecode.payload[client_id];//jwtdecode.payload.azp;//TODO add in config								
							} else {
								debug("ERROR - JWT is invalid");
							}						
						}
					}
				} else {
					debug ("ERROR - JWT Token Missing in Auth header");
				} 
			} catch (err) {
				debug("ERROR - " + err);
			}
			next();
		}
	};
}