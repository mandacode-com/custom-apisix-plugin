local core = require("apisix.core")
local jwt = require("resty.jwt")
local validators = require("resty.jwt-validators")

local schema = {
	type = "object",
	properties = {
		key = { type = "string" }, -- Consumer key to be set in the request header
		key_header = { type = "string", default = "X-Consumer-Key" }, -- Header name to set the consumer key
		force_auth = { type = "boolean", default = false }, -- Whether to force authentication
		secret = { type = "string" }, -- Secret key for JWT verification
		algorithm = {
			type = "string",
			enum = { "HS256", "RS256" }, -- Supported algorithms for JWT
			default = "RS256", -- Default algorithm
		},
		payload_mapping = {
			type = "array",
			items = {
				type = "object",
				properties = {
					claim = { type = "string" },
					header = { type = "string" },
				},
				required = { "claim", "header" },
			},
			default = {
				{ claim = "sub", header = "X-User-ID" },
				{ claim = "exp", header = "X-User-Exp" },
				{ claim = "iat", header = "X-User-Iat" },
			},
		}, -- Mapping of JWT claims to request headers
	},
	required = { "key", "secret" }, -- Required fields for the plugin configuration
	additionalProperties = false,
}

local plugin_name = "custom-jwt-auth"

local _M = {
	version = 0.1,
	priority = 1000,
	name = plugin_name,
	schema = schema,
}

local claim_spec = {
	sub = validators.matches("^[0-9a-fA-F]{8}%-[0-9a-fA-F]{4}%-[0-9a-fA-F]{4}%-[0-9a-fA-F]{4}%-[0-9a-fA-F]{12}$"),
	exp = validators.is_not_expired(),
	iat = validators.is_not_before(),
}

-- @function check_schema
function _M.check_schema(conf)
	return core.schema.check(schema, conf)
end

-- @function get_bearer_token
local function get_bearer_token(header)
	if not header then
		return nil
	end

	if header:sub(1, 7):lower() == "bearer " then
		return header:sub(8)
	end

	return nil
end

-- @function verify_jwt
local function verify_jwt(token, key, algorithm)
	local jwt_obj = jwt:load_jwt(token)
	if not jwt_obj.valid or not jwt_obj.payload then
		core.log.warn("Invalid JWT token: ", jwt_obj.reason or "unknown reason")
		return nil, "Invalid JWT token"
	end

	if not jwt_obj.valid then
		core.log.warn("JWT token is not valid: ", jwt_obj.reason or "unknown reason")
		return nil, "JWT token is not valid"
	end

	if not jwt_obj.payload then
		core.log.warn("JWT payload is missing")
		return nil, "JWT payload is missing"
	end

	if jwt_obj.header.alg ~= algorithm then
		core.log.warn("JWT algorithm mismatch: expected ", algorithm, ", got ", jwt_obj.header.alg)
		return nil, "JWT algorithm mismatch"
	end

	local jwt_verified = jwt:verify_jwt_obj(key, jwt_obj, claim_spec)

	if not jwt_verified.verified then
		core.log.warn("JWT verification failed: ", jwt_verified.reason or "unknown reason")
		return nil, "JWT verification failed"
	end

	if not jwt_verified.payload then
		return nil, "JWT payload is missing"
	end

	return jwt_verified.payload, nil
end

-- @function access
function _M.access(conf, ctx)
	local auth_header = core.request.header(ctx, "authorization")
	local token = get_bearer_token(auth_header)

	if not token then
		core.log.warn("Missing or invalid Authorization header")
		if conf.force_auth then
			core.response.exit(401, { message = "Missing or Invalid Authorization header" })
		end
		return
	end

	local payload, err = verify_jwt(token, conf.secret, conf.algorithm)
	if not payload then
		core.log.warn("JWT verification failed: ", err)
		if conf.force_auth then
			core.response.exit(401, { message = err })
		end
		return
	end

	-- Map JWT claims to headers
	for _, mapping in ipairs(conf.payload_mapping) do
		local claim_value = payload[mapping.claim]
		if claim_value then
			core.request.set_header(ctx, mapping.header, claim_value)
		end
	end

	-- Set the consumer key in the request header
	core.log.info("JWT token verified and headers set for consumer: ", conf.key)
	core.request.set_header(ctx, conf.key_header, conf.key)
end

return _M
