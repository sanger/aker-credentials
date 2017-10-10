require 'spec_helper'
require 'active_support/time'
require 'faraday'

RSpec.describe AkerCredentialsGem do
  let(:rails) { double('Rails') }

  let(:credentials_class) do
     class Credentials_Class
       def self.before_action(symbol)
       end
       def Rails
         rails
       end
       include JWTCredentials
     end
  end

  before(:all) do
    @secret_key = "top_secret"
    @user_hash = {"email"=>"test@sanger.ac.uk", "groups"=>["world"]}

    iat = Time.now.to_i
    exp = Time.now.to_i + 3600
    nbf = Time.now.to_i - 5

    valid_data = { data: @user_hash,
                   exp: exp,
                   nbf: nbf,
                   iat: iat }

    expired_data = { data: @user_hash,
                     exp: (Time.now - 1.seconds),
                     nbf: (Time.now - 35.seconds),
                     iat: (Time.now - 30.seconds) }

    @valid_jwt = JWT.encode valid_data, @secret_key, 'HS256'
    @tampered_jwt = JWT.encode valid_data, "wrong_key", 'HS256'
    @expired_jwt = JWT.encode expired_data, @secret_key, 'HS256'
  end

  before(:each) do
    @credentials_instance = credentials_class.new
    request = double('request', headers: nil)
    allow(@credentials_instance).to receive(:request).and_return(request)
    allow(@credentials_instance).to receive(:secret_key).and_return(@secret_key)
  end

  it "requests a JWT to replace an expired one" do
    cookies = {aker_user_jwt: @expired_jwt}
    allow(@credentials_instance).to receive(:cookies).and_return(cookies)

    # The following exception shows an attempt at sending a request to the auth service
    expect {@credentials_instance.check_credentials}.to raise_exception(Faraday::ConnectionFailed)
  end

  it "doesn't generate a user from a tampered_jwt" do
    cookies = {aker_user_jwt: @tampered_jwt}
    allow(@credentials_instance).to receive(:cookies).and_return(cookies)

    @credentials_instance.check_credentials
  end

  it "redirects a user with no JWT (or session) cookie to login" do
    cookies = {}
    allow(@credentials_instance).to receive(:cookies).and_return(cookies)
    @credentials_instance.check_credentials
  end

  it "accepts a valid JWT" do
    cookies = {aker_user_jwt: @valid_jwt}
    allow(@credentials_instance).to receive(:cookies).and_return(cookies)

    # Ensures the user respresented by @valid_jwt is returned
    expect(@credentials_instance.check_credentials).to eq(OpenStruct.new(@user_hash))
  end

  context 'the thing' do
    let(:logger) { double('Logger') }
    before do
      allow(rails).to receive(:logger).and_return(logger)
      allow(logger).to receive(:warn)
    end

    it '...' do

      ....

      expect(logger).to have_received(:warn).with(...)

    end
  end



end
