require 'spec_helper'
require 'active_support/time'
require 'faraday'

RSpec.describe AkerCredentialsGem do
  let(:rails) { double('Rails', logger: logger, configuration: config) }
  let(:logger) do
    log = double('Logger')
    allow(log).to receive(:warn)
    log
  end

  let(:config) { double('config', login_url: 'http://loginurl') }
  let(:request) { double('request', headers: {}, ip: '1', original_url: 'http://originalurl') }
  let(:jwt_key) { 'top_secret' }
  let(:userhash) { {"email"=>"test@sanger.ac.uk", "groups"=>["world"] } }

  let(:valid_jwt) do
    iat = Time.now.to_i
    exp = iat + 3600
    nbf = iat - 5
    payload = {
      data: userhash, iat: iat, exp: exp, nbf: nbf
    }
    JWT.encode payload, jwt_key, 'HS256'
  end
  let(:expired_jwt) do
    iat = Time.now.to_i-10
    exp = iat + 5
    nbf = iat - 5
    payload = {
      data: userhash, iat: iat, exp: exp, nbf: nbf
    }
    JWT.encode payload, jwt_key, 'HS256'
  end
  let(:invalid_jwt) do
    iat = Time.now.to_i
    exp = iat + 3600
    nbf = iat - 5
    payload = {
      data: userhash, iat: iat, exp: exp, nbf: nbf
    }
    JWT.encode payload, 'wrong_key', 'HS256'
  end
  let(:cookies) { {} }

  class CredentialsClass
    def self.before_action(symbol)
    end
    include JWTCredentials
  end

  let(:credentials_instance) { CredentialsClass.new }

  before do
    allow(config).to receive(:jwt_secret_key).and_return jwt_key
    allow(credentials_instance).to receive(:cookies).and_return(cookies)
    allow(credentials_instance).to receive(:request).and_return(request)
    stub_const('Rails', rails)
  end

  describe(:check_credentials) do
    context 'when the JWT is valid' do
      let(:cookies) { { aker_user_jwt: valid_jwt } }
      it 'extracts the user' do
        credentials_instance.check_credentials
        x = credentials_instance.x_auth_user
        expect(x).not_to be_nil
        expect(x.email).to eq(userhash["email"])
      end
    end

    context 'when the JWT has expired' do
      let(:cookies) { { aker_user_jwt: expired_jwt } }
      before do
        allow(credentials_instance).to receive(:request_jwt)
        credentials_instance.check_credentials
      end
      it 'calls request_jwt' do
        expect(credentials_instance).to have_received(:request_jwt)
      end
      it 'does not store the user' do
        expect(credentials_instance.x_auth_user).to be_nil
      end
    end

    context 'when the JWT is invalid' do
      let(:cookies) { { aker_user_jwt: invalid_jwt } }

      before do
        allow(credentials_instance).to receive(:redirect_to)
        allow(cookies).to receive(:delete)
        credentials_instance.check_credentials
      end
      it 'logs a warning' do
        expect(logger).to have_received(:warn)
      end
      it 'redirects to login url' do
        expect(credentials_instance).to have_received(:redirect_to).with(config.login_url)
      end
      it 'deletes the cookies' do
        expect(cookies).to have_received(:delete).with(:aker_auth_session)
        expect(cookies).to have_received(:delete).with(:aker_user_jwt)
      end
      it 'does not store the user' do
        expect(credentials_instance.x_auth_user).to be_nil
      end
    end

  end

  describe(:request_jwt) do
    let(:conn) { double("Faraday") }
    let(:cookie_data) { '[cookie data]'}
    let(:auth_response) { double('auth response', status: auth_status, headers: { 'set-cookie' => cookie_data}) }
    let(:response) { double('response', headers: headers)}
    let(:headers) { {} }
    before do
      allow(credentials_instance).to receive(:redirect_to)
      allow(credentials_instance).to receive(:response).and_return(response)
      allow(Faraday).to receive(:new).and_return(conn)
      allow(conn).to receive(:post).and_return(auth_response)
      credentials_instance.request_jwt
    end

    context 'when the request succeeds' do
      let(:auth_status) { 200 }

      it 'sends back a cookie' do
        expect(headers['set-cookie']).to eq(cookie_data)
      end

      it 'redirects to the original url' do
        expect(credentials_instance).to have_received(:redirect_to).with(request.original_url)
      end
    end

    context 'when the request fails' do
      let(:auth_status) { 401 }

      it 'does not send back a cookie' do
        expect(headers['set-cookie']).to be_nil
      end

      it 'redirects to the login page' do
        expect(credentials_instance).to have_received(:redirect_to).with(config.login_url)
      end
    end

  end
end
