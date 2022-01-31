import {APIGatewayProxyEvent, APIGatewayRequestAuthorizerEvent} from "aws-lambda"
import {handleRequest} from "./handler"
import Configuration from "./configuration"
import dotenv from "dotenv"
import {handle} from "./optionsHandler";

dotenv.config()

exports.handler = async (event: APIGatewayRequestAuthorizerEvent) => {
    return handleRequest(event, getConfiguration())
};

exports.public = async (event: APIGatewayProxyEvent) => {
    return handle(event, getConfiguration())
}

const getConfiguration = () => new Configuration(
    process.env.TRUSTED_WEB_ORIGINS || "",
    process.env.COOKIE_NAME_PREFIX || "",
    process.env.ENCRYPTION_KEY || "",
    process.env.USE_PHANTOM_TOKEN === "true",
    process.env.INTROSPECTION_URL || "",
    process.env.CLIENT_ID || "",
    process.env.CLIENT_SECRET || "",
)
