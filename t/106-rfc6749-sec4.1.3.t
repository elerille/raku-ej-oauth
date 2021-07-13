# Test RFC6749 section 4.1.3 (https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)

use Test;
use Test::Util::ServerPort;
use URL;
use Cro::HTTP::Server;
use Cro::HTTP::Router;
use URI::Encode;

use Ej::OAuth :ALL;

plan 3;

my Int:D $server-port = get-unused-port;
#my Int:D $client-port = get-unused-port;
my Str:D $endpoint-authorization = "http://localhost:$server-port/authorization";
my Str:D $endpoint-token = "http://localhost:$server-port/token";
my Str:D $endpoint-redirection = "http://localhost/redirect";
my Str:D $expected-client-id = "MyClIeNtId";
my Str:D $expected-client-secret = "MyClIeNtSeCrEt";
my Str:D $expected-code = "MyCoDe";
my Str:D $expected-token = "MyToKeN";

enum MyScope <A B C>;

my OAuth:D $oauth .= new: :scope(MyScope),
                          :$endpoint-authorization,
                          :$endpoint-token,
                          :$endpoint-redirection,
                          client-id => $expected-client-id,
                          client-secret => $expected-client-secret,
                          ;

my MyScope:D @scope = A, B;

my $authorization = $oauth.authorization: Confidential,
                                          :@scope;

my $state = URL.new($authorization.url).query<state>;


my $mock-server = Cro::HTTP::Server.new:
        :host<localhost>, :port($server-port),
        application => route {
            post -> *@path, | {
                diag "Verify no other process/people send a http request to the test server";
                flunk "Request to a non-ok page (POST /{ @path.join('/') })";
            }
            get -> *@path, | {
                diag "Verify no other process/people send a http request to the test server";
                flunk "Request to a non-ok page (GET /{ @path.join('/') })";
            }
            post -> 'token' {
                request-body -> (:$grant_type, :$code, :$redirect_uri, :$client_id,
                                 :$client_secret) {
                    subtest "Request sent to authorization server", {
                        plan 5;
                        is $grant_type, 'authorization_code', "grant_type is authorization_code";
                        is $code, $expected-code, "good code receive";
                        is $redirect_uri, $endpoint-redirection, "good redirect uri receive";
                        is $client_id, $expected-client-id, "good client_id receive";
                        is $client_secret, $expected-client-secret, "good client_secret receive";
                    }
                    content "application/json", {
                        access_token => $expected-token,
                        token_type => "bearer",
                    };
                }
            }
        };
$mock-server.start;
$oauth.authorization-response(:$state, code => $expected-code);
$mock-server.stop;


is $authorization.status, Kept, "Authorization is done";
my $r = $authorization.result;
isa-ok $r, Ej::OAuth::Authorization:D, "Authorization is good type";

#    is $r.token, $expected-token, "token is valid";
#    is $r.type, "bearer", "token type is 'bearer'";
#    nok $r.expires.defined, "No expires is defined";
#    is $r.scope.elems, 0, "No scope is retourned by server";
#    is-deeply $r.scope-asked, @scope.Set, "Scope asked is preserved";

done-testing;
