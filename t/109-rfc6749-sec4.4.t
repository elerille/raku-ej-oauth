# Test RFC6749 section 4.4 (https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)

use Test;
use Test::Util::ServerPort;
use URL;
use Cro::HTTP::Server;
use Cro::HTTP::Router;
use URI::Encode;

use Ej::OAuth :ALL;

plan 4;

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


my $mock-server = Cro::HTTP::Server.new:
        :host<localhost>, :port($server-port),
        application => route {
            post -> *@path { flunk "Request to a non-ok page (POST /{ @path.join('/') })"; }
            get -> *@path { flunk "Request to a non-ok page (GET /{ @path.join('/') })"; }
            post -> 'token' {
                request-body -> (:$grant_type, :$scope, :$client_id, :$client_secret) {
                    subtest "Request sent to authorization server", {
                        plan 4;
                        is $grant_type, 'client_credentials', "grant_type is password";
                        is $scope, "A", "good scope receive 'A'";
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
my $authorization = $oauth.authorization: :client, :scope(A,);
$mock-server.stop;

isa-ok $authorization.url, Str:U, "Url isn't defined";

is $authorization.status, Kept, "Authorization is done";
my $r = $authorization.result;
isa-ok $r, Ej::OAuth::Authorization:D, "Authorization is good type";

done-testing;
