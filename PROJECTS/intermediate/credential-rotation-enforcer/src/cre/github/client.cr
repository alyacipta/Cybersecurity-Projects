# ===================
# ©AngelaMos | 2026
# client.cr
# ===================

require "http/client"
require "json"

module CRE::Github
  class GithubError < Exception
    getter status : Int32

    def initialize(message : String, @status : Int32)
      super(message)
    end
  end

  # Thin GitHub REST client. We target fine-grained PATs for rotation since the
  # /user/personal-access-tokens endpoint accepts programmatic creation /
  # deletion when the bearer token has the appropriate Apps-managed permission.
  # For the test/portfolio path we mock these endpoints directly.
  class Client
    record Token, id : Int64, token_value : String, expires_at : String?

    DEFAULT_API = "https://api.github.com"

    def initialize(@token : String, @api_base : String = DEFAULT_API)
    end

    def me : JSON::Any
      get("/user")
    end

    def create_pat(name : String, scopes : Array(String), expires_in_days : Int32 = 90) : Token
      payload = {
        "name"            => name,
        "expires_in_days" => expires_in_days,
        "scopes"          => scopes,
      }.to_json
      json = post("/user/personal-access-tokens", payload)
      Token.new(
        id: json["id"].as_i64,
        token_value: json["token"].as_s,
        expires_at: json["expires_at"]?.try(&.as_s),
      )
    end

    def delete_pat(token_id : Int64) : Nil
      delete("/user/personal-access-tokens/#{token_id}")
    end

    private def get(path : String) : JSON::Any
      response = HTTP::Client.get(url(path), headers: headers)
      raise GithubError.new("GET #{path}: #{response.body[0, 200]?}", response.status_code) unless response.status_code < 300
      JSON.parse(response.body)
    end

    private def post(path : String, body : String) : JSON::Any
      response = HTTP::Client.post(url(path), headers: headers, body: body)
      raise GithubError.new("POST #{path}: #{response.body[0, 200]?}", response.status_code) unless response.status_code < 300
      JSON.parse(response.body)
    end

    private def delete(path : String) : Nil
      response = HTTP::Client.delete(url(path), headers: headers)
      raise GithubError.new("DELETE #{path}: #{response.body[0, 200]?}", response.status_code) unless response.status_code < 300
    end

    private def headers : HTTP::Headers
      HTTP::Headers{
        "Authorization"        => "Bearer #{@token}",
        "Accept"               => "application/vnd.github+json",
        "X-GitHub-Api-Version" => "2022-11-28",
        "Content-Type"         => "application/json",
      }
    end

    private def url(path : String) : String
      "#{@api_base}#{path}"
    end
  end
end
