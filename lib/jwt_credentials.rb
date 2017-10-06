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
    # JWT present in header (microservices or current SSO)
    if request.headers.to_h['HTTP_X_AUTHORISATION']
      begin
        user_from_jwt(request.headers.to_h['HTTP_X_AUTHORISATION'])
      rescue JWT::VerificationError => e
        render body: nil, status: :unauthorized
      rescue JWT::ExpiredSignature => e
        render body: nil, status: :unauthorized
      end
    # JWT present in cookie (front-end services on new SSO) as well as logged in auth session
  elsif cookies[:aker_user_jwt] && cookies.encrypted[:aker_auth_session]['email']
      begin
        user_from_jwt(cookies[:aker_user_jwt])
      rescue JWT::VerificationError => e
        # TODO: Potential hacking attempt so log this?
        render body: 'JWT in cookie has failed verification', status: :unauthorized
      rescue JWT::ExpiredSignature => e
        request_jwt
      end
    # Logged has logged in auth service session, no JWT, so try get one
  elsif cookies.encrypted[:aker_auth_session]['email']
      request_jwt
    # Fake JWT User for development
    elsif Rails.configuration.respond_to? :default_jwt_user
      build_user(Rails.configuration.default_jwt_user)
    end
  end

  def jwt_provided?
    x_auth_user.present?
  end

  def user_from_jwt(jwt_container)
    secret_key = Rails.configuration.jwt_secret_key
    payload, header = JWT.decode jwt_container, secret_key, true, algorithm: 'HS256'
    build_user(payload['data'])
  end

  def request_jwt
    # Request a new JWT from the auth service
    conn = Faraday.new(url: 'http://localhost:4321')
    response = conn.post do |req|
      req.url '/renew_jwt'
      req.body = cookies.encrypted[:aker_auth_session]['email']
    end
    # Update the JWT Cookie to contain the new JWT
    if response.body.present?
      cookies[:aker_user_jwt] = response.body
    end
    # Redirect user back to the URL they were trying to get access
    redirect_to request.original_url
  end

end
