# Sample Plugin - Azure OAuth

## Overview
This plugin integrates with [Azure's OAuth Auth server](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code). The integration will rely on portions of the [RFC 7523](https://tools.ietf.org/html/rfc7523) (JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants) specification. Azure’s OAuth token endpoint will issue a JWT Token that contains an API Key (aka client_id or consumer key) that is known to Apigee.
 
The RFC7523 specification requires the “client_id” to appear in the “sub” (subject) claim of the JWT Token. However, Azure includes the “client_id” in the “azp” (Authorized Party) claim on the JWT Token.
 
Apigee Edge Microgateway will validate the JWT and the API Key contained within it.

## Enable the plugin
Include the plugin the in plugin sequence of {org}-{env}-config.yaml file. This plugin *MUST* appear before the OAuth plugin.
```
  plugins:
    sequence:
      - azurejwt
      - oauth
```

## Configure the plugin
The plugin configuration has three parts:
* Specify the endpoint where the public keys (for JWT validation) are found
* Specify the location of the client_id in the JWT
* OPTIONAL: specify the issuer (for validation)
* OPTIONAL: check for expiry (true/false)
```
azurejwt:
  publickey_url: https://login.microsoftonline.com/xxx.onmicrosoft.com/discovery/v2.0/keys?p=ccccc
  client_id: azp
  iss: https://login.microsoftonline.com/xxx/v2.0/
  exp: true
```

## Import Azure client_id to Apigee
```
curl  -H 'Content-type:application/json' -n https://api.enterprise.apigee.com/v1/organizations/{org}/developers/sample@apigee.com/apps -X POST -d '{"name" : "AzureApp","status" : "approved"}' -v
 
curl -H 'Content-type:application/json' -n https://api.enterprise.apigee.com/v1/organizations/{org}/developers/sample@apigee.com/apps/AzureApp/keys/create -X POST -d '{"consumerKey": "bxxx2", "consumerSecret": "bzzz3"}' -v
```

## How does it work?
The microgateway plugin validates the JWT, extracts the client_id (azp) claim and passes it to the API Key verification plugin (the OAuth plugin doubles as an API Key verification plugin also).
