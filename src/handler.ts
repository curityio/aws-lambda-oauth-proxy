/*
 *  Copyright 2022 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import Configuration from './configuration'
import decryptCookie from './cookieDecrypter'
import { parse } from 'cookie'
import {
  APIGatewayRequestAuthorizerEvent, AuthResponse, Statement
} from "aws-lambda"
import * as https from 'https'
import {URL, URLSearchParams} from "url";
import {RequestOptions} from "https";
import TokenExpired from "./TokenExpired";
import IntrospectionException from "./IntrospectionException";

export async function handleRequest(
  event: APIGatewayRequestAuthorizerEvent,
  config: Configuration
): Promise<AuthResponse> {

  const singleValueHeaders = event.headers || {}
  const originFromHeader = singleValueHeaders['origin'] || singleValueHeaders['Origin'] || ''

  if (config.allowToken) {
    // If there is already a bearer token, eg for mobile clients, return immediately
    // Note that the target API must always digitally verify the JWT access token
    const authorizationHeader = singleValueHeaders['authorization'] || singleValueHeaders['Authorization']

    if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
      const token = authorizationHeader.substring(7);
      const iamPolicy = generateIAMPolicy(token, event.methodArn)
      iamPolicy.context = {
        "token": authorizationHeader,
      }
      return iamPolicy
    }
  }

  // For cookie requests, verify the web origin in line with OWASP CSRF best practices
  if (config.trustedOrigins.length) {
    if (!config.trustedOrigins.includes(originFromHeader)) {
      console.warn(
        `The ${event.httpMethod} request to ${event.path} was from an untrusted web origin: ${originFromHeader}. Trusted origins: ${config.trustedOriginsString}`,
      )
      return generateDenyIAMPolicy('anonymous', event.methodArn)
    }
  }

  const cookies = parse(singleValueHeaders['cookie'] || singleValueHeaders['Cookie'] || '')
  const dataChangingMethods = ['POST', 'PUT', 'DELETE', 'PATCH']

  // For data changing requests do double submit cookie verification in line with OWASP CSRF best practices
  if (dataChangingMethods.includes(event.httpMethod)) {
    const csrfCookieName = config.cookieNamePrefix + '-csrf'
    const csrfEncryptedCookie = cookies[csrfCookieName]

    if (!csrfEncryptedCookie) {
      console.warn(
        `No CSRF cookie was sent with the ${event.httpMethod} request to ${event.path}`,
      )
      return generateDenyIAMPolicy('anonymous', event.methodArn)
    }

    let csrfTokenFromCookie = ''

    try {
      csrfTokenFromCookie = await decryptCookie(
        csrfEncryptedCookie,
        config.encryptionKey,
      )
    } catch (error: any) {
      console.warn(
          `Error decrypting CSRF cookie ${csrfEncryptedCookie} during ${event.httpMethod} request to ${event.path}.`,
          error.message,
      )
      return generateDenyIAMPolicy('anonymous', event.methodArn)
    }

    const csrfTokenFromHeader = singleValueHeaders['x-' + csrfCookieName]
    if (csrfTokenFromHeader !== csrfTokenFromCookie) {
      console.warn(
          `Invalid or missing CSRF request header ${csrfTokenFromHeader} during ${event.httpMethod} request to ${event.path}. CSRF token from cookie: ${csrfTokenFromCookie}`,
      )
      return generateDenyIAMPolicy('anonymous', event.methodArn)
    }
  }

  // Next verify that the main cookie was received and get the access token
  const accessTokenEncryptedCookie = cookies[config.cookieNamePrefix + '-at']
  if (!accessTokenEncryptedCookie) {
    console.warn(
        `No access token cookie was sent with the ${event.httpMethod} request to ${event.path}`,
    )
    return generateDenyIAMPolicy('anonymous', event.methodArn)
  }

  // Decrypt the access token cookie, which is encrypted using AES256
  let accessToken: string

  try {
    accessToken = await decryptCookie(
      accessTokenEncryptedCookie,
      config.encryptionKey,
    )
  } catch (error) {
    console.warn(
      `Error decrypting access token cookie ${accessTokenEncryptedCookie} during ${event.httpMethod} request to ${event.path}`,
    )
    return generateDenyIAMPolicy('anonymous', event.methodArn)
  }

  const iamPolicy = generateIAMPolicy(accessToken, event.methodArn)
  let policyContext = {} as any;

  if (config.phantomToken) {
    try {
      accessToken = await exchangePhantomToken(accessToken, config)
    } catch (error: any) {
      if (error instanceof TokenExpired) {
        // Promise has to be rejected with the string "Unauthorized". This way the lambda authorizer returns a 401 to the client.
        // Currently, there is no nicer way of returning a 401 from a lambda authorizer.
        return Promise.reject("Unauthorized")
      }
      if (error instanceof IntrospectionException) {
        return generateDenyIAMPolicy('anonymous', event.methodArn)
      }
    }
  }

    // Add the access token to context making it available to API GW to add to upstream Authorization header
    iamPolicy.context = {
      "token": 'Bearer ' + accessToken
    };

  return iamPolicy
}

function generateIAMPolicy(principal: string, methodArn: string): AuthResponse {
  const policyStatements = []

  //Wildcard path generated with getServiceArn. Needed if IAM policies are cached and multipe API paths are using the Authorizer.
  policyStatements.push(generatePolicyStatement(getServiceArn(methodArn), "Allow"))
  return generatePolicy(principal, policyStatements)
}

function generateDenyIAMPolicy(principal: string, methodArn: string): AuthResponse {
  const policyStatements = []

  //Wildcard path generated with getServiceArn. Needed if IAM policies are cached and multipe API paths are using the Authorizer.
  policyStatements.push(generatePolicyStatement(getServiceArn(methodArn), "Deny"))

  return generatePolicy(principal, policyStatements)
}

function generatePolicyStatement(methodArn: string, action: string): Statement {
  return {
    Action: 'execute-api:Invoke',
    Effect: action,
    Resource: methodArn
  }
}

function getServiceArn(methodArn: string): string {

  // Get the last part, such as cqo3riplm6/default/GET/products
  const parts = methodArn.split(':');
  if (parts.length === 6) {

    // Split the path into parts
    const pathParts = parts[5].split('/');
    if (pathParts.length >= 4) {

      // Update the final part to a wildcard value such as cqo3riplm6/mystage/*, to apply to all lambdas in the API
      parts[5] = `${pathParts[0]}/${pathParts[1]}/*`;
      return parts.join(':')
    }
  }

  // Sanity check
  throw new Error(`Unexpected method ARN received: ${methodArn}`);
}

function generatePolicy(principalId: string, policyStatements: Statement[]): AuthResponse {
  return {
    principalId: principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: policyStatements,
    }
  }
}

/* Introspect access token */
function introspect(options: RequestOptions, data: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      if (res.statusCode == 204) {
        return reject(new TokenExpired())
      }

      res.setEncoding("utf8");
      let responseBody = "";

      res.on("data", (chunk) => {
        responseBody += chunk;
      });

      res.on("end", () => {
        if (res.statusCode != 200) {
          console.warn(`Received error response when calling introspection endpoint. Status code: ${res.statusCode}, body: ${responseBody}`)
          return reject(new IntrospectionException())
        }

        resolve(responseBody);
      });
    });

    req.on("error", (err) => {
      reject(err);
    });

    req.write(data);
    req.end();
  });
}

async function exchangePhantomToken(accessToken: string, configuration: Configuration): Promise<string> {

  const data = new URLSearchParams();
  data.append('token', accessToken);

  //Base64 encode client_id and client_secret to authenticate Introspection endpoint
  const introspectCredentials = Buffer.from(configuration.clientID + ":" + configuration.clientSecret, 'utf-8').toString('base64');

  const introspectionUrl = new URL(configuration.introspectionURL)

  const options = {
    host: introspectionUrl.host,
    path: introspectionUrl.pathname,
    port: introspectionUrl.port,
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + introspectCredentials,
      'Accept': 'application/jwt',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': data.toString().length
    }
  };

    return await introspect(options, data.toString());
}
