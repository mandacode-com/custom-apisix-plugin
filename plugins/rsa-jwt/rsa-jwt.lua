local core = require("apisix.core")
local jwt = require("resty.jwt")
local validators = require("resty.jwt-validators")

local schema = {
	type = "object",
	properties = {
		force_auth = { type = "boolean", default = false },
		access_public_key = { type = "string" },
		gateway_jwt_secret = { type = "string" },
		gateway_jwt_header = { type = "string", default = "X-Gateway-JWT" },
		gateway_jwt_exp = { type = "integer", default = 30 },
		gateway_jwt_iss = { type = "string", default = "api-gateway" },
		gateway_jwt_aud = { type = "string", default = "default-app" },
		payload_keys = {
			type = "array",
			items = {
				type = "string",
			},
			default = {
				"uuid",
				"role",
			},
		},
	},
	required = { "access_public_key", "gateway_jwt_secret" },
	additionalProperties = false,
}

local plugin_name = "rsa-jwt"

local _M = {
	version = 0.1,
	priority = 1000,
	name = plugin_name,
	schema = schema,
}

-- @function unauthorized
local function unauthorized(message)
	core.response.exit(401, { message = message })
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
local function verify_jwt(token, public_key)
	local jwt_obj = jwt:load_jwt(token)
	if not jwt_obj.valid or not jwt_obj.payload then
		return nil, "Invalid JWT token"
	end

	local claim_spec = {
		exp = validators.is_not_expired(),
		iat = validators.is_not_before(),
	}

	local jwt_verify = jwt:verify_jwt_obj(public_key, jwt_obj, claim_spec)

	if not jwt_verify.verified then
		return nil, "JWT verification failed"
	end

	return jwt_obj.payload, nil
end

-- @function create_jwt
local function create_jwt(payload, secret)
	local signed_jwt = jwt:sign(secret, {
		header = { typ = "JWT", alg = "HS256" },
		payload = payload,
	})

	return signed_jwt
end

-- @function check_schema
function _M.check_schema(conf)
	return core.schema.check(schema, conf)
end

-- @function access
function _M.access(conf, ctx)
	local auth_header = core.request.header(ctx, "authorization")
	local token = get_bearer_token(auth_header)

	-- empty gateway jwt header
	core.request.set_header(ctx, conf.gateway_jwt_header, nil)

	if not token then
		if conf.force_auth then
			unauthorized("Missing or Invalid Authorization header")
		end
		return
	end

	local payload, err = verify_jwt(token, conf.access_public_key)
	if not payload then
		if conf.force_auth then
			unauthorized(err)
		end
		return
	end

	local now = ngx.time()
	local filtered_payload = {
		exp = now + conf.gateway_jwt_exp,
		iat = now,
		iss = conf.gateway_jwt_iss,
		aud = conf.gateway_jwt_aud,
	}
	for _, key in ipairs(conf.payload_keys) do
		local value = payload[key]
		if value then
			filtered_payload[key] = value
		end
	end

	local gateway_jwt = create_jwt(filtered_payload, conf.gateway_jwt_secret)
	core.request.set_header(ctx, conf.gateway_jwt_header, gateway_jwt)
end

return _M
