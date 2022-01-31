import {CorsHeaders} from "./bindings";
import Configuration from "./configuration";

const emptyCorsHeaders = {} as CorsHeaders;

export default function getCorsHeaders(config: Configuration, origin: string, isError: boolean = false, withMethods: boolean = false): CorsHeaders {
    const corsHeaders = emptyCorsHeaders

    if (config.trustedOrigins.includes(origin)) {
        if (isError || config.allowCors) {
            corsHeaders["access-control-allow-origin"] = origin
            corsHeaders["access-control-allow-credentials"] = true
        }

        if (config.allowCors) {
            if (withMethods) {
                corsHeaders["access-control-allow-methods"] = config.allowMethods
            }
            corsHeaders["access-control-max-age"] = config.corsMaxAge
            corsHeaders["access-control-allow-headers"] = config.allowHeaders
            corsHeaders["access-control-expose-headers"] = config.exposeHeaders
        }
    }

    return corsHeaders
}
