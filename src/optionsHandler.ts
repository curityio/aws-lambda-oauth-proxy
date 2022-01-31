import {APIGatewayProxyEvent, APIGatewayProxyResult} from "aws-lambda";
import getCorsHeaders from "./cors";
import Configuration from "./configuration";

export async function handle(event: APIGatewayProxyEvent, config: Configuration): Promise<APIGatewayProxyResult> {
    // Return proper CORS headers for OPTIONS requests
    if (event.httpMethod == 'OPTIONS') {
        event = event as APIGatewayProxyEvent
        const corsHeaders = getCorsHeaders(config, event.headers['origin'] || '', false, true)
        return {
            statusCode: 200,
            body: "",
            headers: corsHeaders
        } as APIGatewayProxyResult
    }

    // For other methods return 404
    return {
        statusCode: 404,
        body: ""
    } as APIGatewayProxyResult
}
