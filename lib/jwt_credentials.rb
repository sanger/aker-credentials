require 'jwt'
require 'ostruct'
require 'request_store'

module JWTCredentials

  def self.included(base)
    base.instance_eval do |klass|
      before_action :check_credentials
      before_action :apply_credentials
    end
  end

  def apply_credentials
    RequestStore.store[:x_authorisation] = current_user
  end

  def build_user(hash)
    if defined? User
      @x_auth_user = User.from_jwt_data(hash)
    else
      @x_auth_user = OpenStruct.new(hash)
    end
  end

  # Override this for cases where the user credentials come from elsewhere,
  #  e.g. a login session
  def current_user
    @x_auth_user
  end

  def check_credentials
    @x_auth_user = nil
    if request.headers.to_h['HTTP_X_AUTHORISATION']
      begin
        secret_key = Rails.configuration.jwt_secret_key
        token = request.headers.to_h['HTTP_X_AUTHORISATION']
        payload, header = JWT.decode token, secret_key, true, { algorithm: 'HS256'}
        ud = payload["data"]
        build_user(ud)
      rescue JWT::VerificationError => e
        render body: nil, status: :unauthorized
      rescue JWT::ExpiredSignature => e
        render body: nil, status: :unauthorized
      end
    else
      build_user("email" => 'guest', "groups" => ['world'])
    end
  end  
end
