# Test RFC6749 section 5.2 (https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)

use Test;
use Test::Util::ServerPort;
use URL;
use Cro::HTTP::Server;
use Cro::HTTP::Router;
use URI::Encode;

use Ej::OAuth :ALL;

plan 14;

my Int:D $server-port = get-unused-port;
#my Int:D $client-port = get-unused-port;
my Str:D $endpoint-authorization = "http://localhost:$server-port/authorization";
my Str:D $endpoint-token = "http://localhost:$server-port/token";
my Str:D $endpoint-redirection = "http://localhost/redirect";
my Str:D $expected-client-id = "MyClIeNtId";
my Str:D $expected-client-secret = "MyClIeNtSeCrEt";
my Str:D $expected-code = "MyCoDe";
my Str:D $expected-token = "MyToKeN";
my Str:D $expected-username = "MyUsErNaMe";
my Str:D $expected-password = "MyPaSsWoRd";

enum MyScope <A B C>;

my OAuth:D $oauth .= new: :scope(MyScope),
                          :$endpoint-authorization,
                          :$endpoint-token,
                          :$endpoint-redirection,
                          client-id => $expected-client-id,
                          client-secret => $expected-client-secret,
                          client-type => Confidential,
                          ;


my @test = ({ :error<invalid_request>, },
            { :type(X::Ej::OAuth::Type::InvalidRequest), :description(Str), :uri(Str) }),
           ({ :error<invalid_client>, },
            { :type(X::Ej::OAuth::Type::InvalidClient), :description(Str), :uri(Str) }),
           ({ :error<invalid_grant>, },
            { :type(X::Ej::OAuth::Type::InvalidGrant), :description(Str), :uri(Str) }),
           ({ :error<unauthorized_client>, },
            { :type(X::Ej::OAuth::Type::UnauthorizedClient), :description(Str), :uri(Str) }),
           ({ :error<unsupported_grant_type>, },
            { :type(X::Ej::OAuth::Type::UnsupportedGrantType), :description(Str), :uri(Str) }),
           ({ :error<invalid_scope>, },
            { :type(X::Ej::OAuth::Type::InvalidScope), :description(Str), :uri(Str) }),
           ({ :error<invalid_request>, :error_description("Ma description perso") },
            { :type(X::Ej::OAuth::Type::InvalidRequest), :description("Ma description perso"), :uri(Str) }),
           ({ :error<invalid_request>, :error_uri("http://example.com/jkdshf") },
            { :type(X::Ej::OAuth::Type::InvalidRequest), :description(Str), :uri("http://example.com/jkdshf") }),
           ({ :error<invalid_request>, :error_description("Ma description perso"),
              :error_uri("http://example.com/jkdshf") },
            { :type(X::Ej::OAuth::Type::InvalidRequest), :description("Ma description perso"),
              :uri("http://example.com/jkdshf") }),
           ({ :error<UnKnOwNeRrOr>, },
            { :type(X::Ej::OAuth::Type::Other), :description("UnKnOwNeRrOr: "), :uri(Str) }),
           ({ :error<UnKnOwNeRrOr>, :error_description("My Description") },
            { :type(X::Ej::OAuth::Type::Other), :description("UnKnOwNeRrOr: My Description"), :uri(Str) }),
           ({ :error<UnKnOwNeRrOr>, :error_uri("http://example.com/qlwe") },
            { :type(X::Ej::OAuth::Type::Other), :description("UnKnOwNeRrOr: "), :uri("http://example.com/qlwe") }),
           ({ :error<UnKnOwNeRrOr>, :error_description("My Description"), :error_uri("http://example.com/qlwe") },
            { :type(X::Ej::OAuth::Type::Other), :description("UnKnOwNeRrOr: My Description"),
              :uri("http://example.com/qlwe") }),
           ({ :error<UnKnOwNeRrOr>, :UnSuPoRtEdFiElD("Value") },
            { :type(X::Ej::OAuth::Type::Other), :description("UnKnOwNeRrOr: "), :uri(Str) }),
           ;

for @test -> (%response, %expected) {
    subtest "Response " ~ ++$ ~ ".", {
        plan 6;
        my $authorization = $oauth.authorization: :scope(A,);
        my $state = URL.new($authorization.url).query<state>;


        my $mock-server = Cro::HTTP::Server.new:
                :host<localhost>, :port($server-port),
                application => route {
                    post -> *@path { flunk "Request to a non-ok page (POST /{ @path.join('/') })"; }
                    get -> *@path { flunk "Request to a non-ok page (GET /{ @path.join('/') })"; }
                    post -> 'token' {
                        request-body -> (:$grant_type, :$code, :$redirect_uri, :$client_id, :$client_secret) {
                            subtest "Request sent to authorization server", {
                                plan 5;
                                is $grant_type, 'authorization_code', "grant_type is authorization_code";
                                is $code, $expected-code, "good code receive";
                                is $redirect_uri, $endpoint-redirection, "good redirect uri receive";
                                is $client_id, $expected-client-id, "good client_id receive";
                                is $client_secret, $expected-client-secret, "good client_secret receive";
                            }
                            content "application/json", %response;
                        }
                    }
                };

        $mock-server.start;
        $oauth.authorization-response(:$state, code => $expected-code);
        $mock-server.stop;


        is $authorization.status, Broken, "Authorization is brokt";
        my $r = $authorization.cause;
        isa-ok $r, X::Ej::OAuth:D, "Cause is X::Ej::OAuth";
        is $r.type, %expected<type>, "Error type is ok";
        is $r.description, %expected<description>, "Error description is ok";
        is $r.uri, %expected<uri>, "Error URI is ok";
    }
}

done-testing;
