require 'jwt'
require 'request_store'
require 'ostruct'
require 'faraday'

# This is only used for generating JWTs for services to communicate with each
# other, NOT for the JWT stored in a cookie.
class JWTSerializer < Faraday::Middleware
  JWT_NBF_TIME = 60
  JWT_EXP_TIME = 120

  def call(env)
    user_info = RequestStore.store[:x_authorisation]
    if user_info
      token = JWTSerializer.generate_jwt(user_info)
      env[:request_headers]["X-Authorisation"] = token
    else
      env[:request_headers].delete("X-Authorisation")
    end
    @app.call(env)
  end

  def self.generate_jwt(auth_hash)
    if auth_hash.is_a? OpenStruct
      auth_hash = auth_hash.to_h
    elsif !auth_hash.is_a? Hash
      auth_hash = auth_hash.to_jwt_data
    end
    secret_key = Rails.application.config.jwt_secret_key
    exp = Time.now.to_i + JWT_EXP_TIME
    nbf = Time.now.to_i - JWT_NBF_TIME

    payload = { data: auth_hash, exp: exp, nbf: nbf }
    JWT.encode payload, secret_key, 'HS256'
  end

end
