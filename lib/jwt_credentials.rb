require 'jwt'
require 'ostruct'
require 'request_store'
require 'jwt_serializer'

module JWTCredentials

  def self.included(base)
    base.instance_eval do |klass|
      before_action :check_credentials
      before_action :apply_credentials
    end
  end

  attr_reader :x_auth_user

  def current_user
    if respond_to?(:auth_user)
      auth_user || x_auth_user
    else
      x_auth_user
    end
  end

  def apply_credentials
    RequestStore.store[:x_authorisation] = current_user
  end

  def build_user(hash)
    @x_auth_user = if defined? User
                     User.from_jwt_data(hash)
                   else
                     OpenStruct.new(hash)
                   end
  end

  def check_credentials
    @x_auth_user = nil
    if request.headers.to_h['HTTP_X_AUTHORISATION']
      # JWT present in header (microservices or current SSO)
      begin
        user_from_jwt(request.headers.to_h['HTTP_X_AUTHORISATION'])
      rescue JWT::VerificationError => e
        render body: nil, status: :unauthorized
      rescue JWT::ExpiredSignature => e
        render body: nil, status: :unauthorized
      end
    elsif cookies[:aker_user_jwt]
      # JWT present in cookie (front-end services on new SSO)
      begin
        user_from_jwt(cookies[:aker_user_jwt])
      rescue JWT::VerificationError => e
        # Potential hacking attempt so log this
        jwt = JWT.decode cookies[:aker_user_jwt], '', false, algorithm: 'HS256'
        Rails.logger.warn("JWT verification failed from #{request.ip}, JWT: #{jwt}")
        # Then delete their cookies
        cookies.delete :aker_auth_session
        cookies.delete :aker_user_jwt
        # TODO: expire their session in the database
        redirect_to login_url
      rescue JWT::ExpiredSignature => e
        request_jwt
      end
    elsif default_user
      # Fake JWT User for development
      build_user(default_user)
    end
  end

  def jwt_provided?
    x_auth_user.present?
  end

  def user_from_jwt(jwt_container)
    payload, header = JWT.decode jwt_container, secret_key, true, algorithm: 'HS256'
    build_user(payload['data'])
  end

  def request_jwt
    # Request a new JWT from the auth service
    conn = Faraday.new(url: auth_service_url)
    auth_response = conn.post do |req|
      req.url '/renew_jwt'
      req.headers['Cookie'] = "aker_auth_session=#{cookies[:aker_auth_session]}"
    end
    if auth_response.status == 200
      # Update the JWT Cookie to contain the new JWT
      # Ensures cookies returned by request to auth service are actually set
      response.headers['set-cookie'] = auth_response.headers['set-cookie']
      # Redirect user back to the URL they were trying to get access
      redirect_to request.original_url
    else
      redirect_to login_url
    end
  end

  def login_url
    Rails.configuration.login_url
  end

  def default_user
    if Rails.configuration.respond_to? :default_jwt_user
      Rails.configuration.default_jwt_user
    else
      nil
    end
  end

  def secret_key
    Rails.configuration.jwt_secret_key
  end

  def auth_service_url
    Rails.configuration.auth_service_url
  end

end
