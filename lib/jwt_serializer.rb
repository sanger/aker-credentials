require 'jwt'
require 'request_store'
require 'ostruct'

class JWTSerializer < Faraday::Middleware

  def call(env)
    #debugger
    token = JWTSerializer.generate_jwt(RequestStore.store[:x_authorisation])
    env[:request_headers]["X-Authorisation"] = token
    @app.call(env)
  end

  def self.generate_jwt(auth_hash)
    #debugger
    if auth_hash.is_a? OpenStruct
      auth_hash = auth_hash.to_h
    elsif !auth_hash.is_a? Hash
      auth_hash = auth_hash.to_jwt_data
    end
    secret_key = Rails.application.config.jwt_secret_key
    exp = Time.now.to_i + Rails.application.config.jwt_exp_time
    nbf = Time.now.to_i - Rails.application.config.jwt_nbf_time

    payload = { data: auth_hash, exp: exp, nbf: nbf }
    JWT.encode payload, secret_key, 'HS256'
  end

end
