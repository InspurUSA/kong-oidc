-- Extending the Base Plugin handler is optional, as there is no real
-- concept of interface in Lua, but the Base Plugin handler's methods
-- can be called from your child implementation and will print logs
-- in your `error.log` file (where all logs are printed).
local BasePlugin = require "kong.plugins.base_plugin"
local CustomHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local cjson = require "cjson"
local oidc = require("resty.openidc")
local http = require "resty.http"

CustomHandler.PRIORITY = 1000

-- Your plugin handler's constructor. If you are extending the
-- Base Plugin handler, it's only role is to instanciate itself
-- with a name. The name is your plugin name as it will be printed in the logs.
function CustomHandler:new()
    CustomHandler.super.new(self, "oidc")
end

function CustomHandler:header_filter(config)
    -- Eventually, execute the parent implementation
    -- (will log that your plugin is entering this context)

    ngx.ctx.KONG_HEADER_FILTER_STARTED_AT = ngx.now()
    CustomHandler.super.header_filter(self)
    -- Implement any custom logic here
end

function CustomHandler:body_filter(config)
    -- Eventually, execute the parent implementation
    -- (will log that your plugin is entering this context)
    ngx.ctx.KONG_HEADER_FILTER_STARTED_AT = ngx.now()
    CustomHandler.super.body_filter(self)

    -- Implement any custom logic here
end

function setUserOr403(user)
    if user then
        utils.injectUser(user)
        ngx.req.set_header("X_USER", user.preferred_username)
        ngx.req.set_header("X_USER_ID", user.id)
        ngx.req.set_header("X_USER_NAME", user.name)
        ngx.req.set_header("X_USER_INFO", require("cjson").encode(user))
    else
        utils.exit(403, 'Not authenticated request', ngx.HTTP_FORBIDDEN)
    end
end

function CustomHandler:access(config)
    -- Eventually, execute the parent implementation
    -- (will log that your plugin is entering this context)
    CustomHandler.super.access(self)

    local oidcConfig = utils.get_options(config, ngx)

    if filter.shouldProcessRequest(oidcConfig) then
        ngx.log(ngx.DEBUG, "In plugin (oidc) CustomHandler:access calling authenticate, requested path: " .. ngx.var.request_uri)
        session.configure(config)
        local accessToken, err = utils.get_bearer_access_token(oidcConfig)     
        local user
        if accessToken then
            ngx.log(ngx.DEBUG, "Found Access token, using it for authentication ")    
            local cachedUser = utils.jwt_cache_get(accessToken)

            if cachedUser then
                user = cjson.decode(cachedUser)
            else

                local headers = {
                    ["Content-Type"] = "application/x-www-form-urlencoded"
                }
                local body = {
                    token = accessToken,
                    discoveryUrl = config.discovery
                }
                local httpc = http.new()
                local jwt_verifier_url = config.jwt_verifier_url
                local res, err = httpc:request_uri(jwt_verifier_url, {
                    method = "POST",
                    body = ngx.encode_args(body),
                    headers = headers,
                    ssl_verify = "no"
                })


                if res.status ~= 200 then
                    ngx.log(ngx.ERR, "response from "..jwt_verifier_url.." indicates failure, status=" .. res.status .. ", body=" .. res.body)
                else
                    -- decode the response and extract the JSON object                 
                    local resParsed = cjson.decode(res.body)
                    if resParsed and resParsed.verification == 'OK' then
                        user = {
                            id = resParsed.sub,
                            name = resParsed.name,
                            preferred_username = resParsed.preferred_username,
                            email = resParsed.email
                        }
                        --        todo: set cache expiration more inline with token expiration, 5minutes for now
                        utils.jwt_cache_set(accessToken, cjson.encode(user), 5 * 60)
                    end

                    if not resParsed then
                        ngx.log(ngx.ERR, "jwt verification failed: response was " .. res.body)
                    end
                end
            end
            setUserOr403(user)
        else
            local res, err = oidc.authenticate(oidcConfig)

            if err then
                if config.recovery_page_path then
                    ngx.log(ngx.DEBUG, "Entering recovery page: " .. config.recovery_page_path)
                    return ngx.redirect(config.recovery_page_path)
                end
                utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
            end

            if res and res.user then
                setUserOr403(res.user)
            end
        end

    else
        ngx.log(ngx.DEBUG, "In plugin CustomHandler:access NOT calling authenticate, requested path: " .. ngx.var.request_uri)
    end

    ngx.log(ngx.DEBUG, "In plugin CustomHandler:access Done")
end

-- This module needs to return the created table, so that Kong
-- can execute those functions.
return CustomHandler
