# The OAuth Proxy component for the AWS Gateway

[![Quality](https://img.shields.io/badge/quality-demo-red)](https://curity.io/resources/code-examples/status/) 
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

An implementation of the Token Handler's OAuth Proxy module for the AWS Gateway. The proxy is implemented as a Lambda Authorizer using Typescript.
Additionally, the configuration of resources and methods in the serverless.yaml shows how to properly setup CORS headers.

The Token Handler is an architectural design in which an SPA uses lightweight backend components in order to keep secure tokens out of the browser and
leverage same-site http-only session cookies instead. You can read more about the concept in [this overview](https://curity.io/resources/learn/token-handler-overview/).

The Token Handler consists of two components:
   - the OAuth Agent, which responsible for issuing secure cookies and handling communication with the Authorization Server
   - the OAuth Proxy, which is responsible for decrypting cookies and passing access tokens to the underlying APIs.

This repository is an implementation of the OAuth Proxy, designed to work as an AWS Lambda Authorizer. The flow goes as follows:

- The lambda authorizer is called with details of the request.
- The authorizer verifies the origin and whether there is a valid access token cookie.
- For data-changing methods, the CSRF token and cookie are validated.
- The access token cookie is decrypted. If [Phantom Token](https://curity.io/resources/learn/phantom-token-pattern) is used, then
  the opaque token is exchanged for a JWT. The access token is then added to the context of the policy returned by the authorizer.
- The gateway then overwrites the Authorization header with the token from the authorizer's context and calls the underlying API.
- The gateway sets proper CORS headers to the responses received from the API.

## Prerequisites

The easiest way to deploy the authorizer is with the use of the [serverless framework](https://www.serverless.com). Make sure to have the `serverless` command line tool installed, and configured it with your [AWS credentials](https://www.serverless.com/framework/docs/providers/aws/guide/credentials).

## Deploying the API

First edit the `serverless.yaml` definition:

1. Set your organisation name, app name and service name.
2. Set endpoints of your API. Every endpoint is described in the file by a Resource entry and Method entries for supported HTTP methods.
   There is an example `DataResource` with methods `PostDataMethod` and `OptionsDataMethod`. You should set the path in the resource entry.
   The Options method entry should be used for all your resources so that CORS headers are properly managed. The example `PostDataMethod` is configured
   to use the lambda authorizer. Make sure to copy the configuration for other methods, as proper authorization and CORS response headers are set using
   the features of the AWS gateway.
3. Copy the `.env-template` file to a `.env` file and set the relevant configuration options. Entries which are commented out show the default values used
   by the authorizer and Gateway.
4. Run `serverless deploy` to deploy the API definition to AWS.

### Manually deploying

You can also manually deploy the authorizer and configure your APIs. Follow these steps to manually deploy and configure the API Gateway with the OAuth Proxy module:

1. Install dependencies and duild the code with `npm i && npm run build`.
2. Create a zip archive containing:
   - files from `.build/`
   - `node_modules` with `cookie` and `dotenv` dependencies
   - `.env` file
3. Create a Lambda function in the AWS console and upload the zip archive.
4. Configure the API according to what is used in the serverless definition:
   - the secured method should have the authorizer enabled
   - the secured method should have a request mapping which populates the Authorization header with the value returned by the authorizer.
   - proper mappings for CORS headers should be added to the response
   - an OPTION method should be added to the resource with proper headers returned
