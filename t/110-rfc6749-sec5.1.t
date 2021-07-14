# Test RFC6749 section 5.1 (https://datatracker.ietf.org/doc/html/rfc6749#section-5.1)

use Test;
use Test::Util::ServerPort;
use URL;
use Cro::HTTP::Server;
use Cro::HTTP::Router;
use URI::Encode;

use Ej::OAuth :ALL;

plan 7;

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


my @test = ({ :access_token<MyToKeN-1>, :token_type<MyTyPe-A>, },
            { :token<MyToKeN-1>, :type<MyTyPe-A>, :refresh-token(Str:U), :expires(Instant:U), :scope(Set.new) }),
           ({ :access_token<MyToKeN-2>, :token_type<MyTyPe-B>, :60expires_in },
            { :token<MyToKeN-2>, :type<MyTyPe-B>, :refresh-token(Str:U), :expires(now + 60), :scope(Set.new) }),
           ({ :access_token<MyToKeN-3>, :token_type<MyTyPe-C>, :60expires_in, :refresh_token<MyReFrEsHtOkEn-1> },
            { :token<MyToKeN-3>, :type<MyTyPe-C>, :refresh-token<MyReFrEsHtOkEn-1>, :expires(now + 60),
              :scope(Set.new) }),
           ({ :access_token<MyToKeN-4>, :token_type<MyTyPe-D>, :refresh_token<MyReFrEsHtOkEn-2> },
            { :token<MyToKeN-4>, :type<MyTyPe-D>, :refresh-token<MyReFrEsHtOkEn-2>, :expires(Instant:U),
              :scope(Set.new) }),
           ({ :access_token<MyToKeN-5>, :token_type<MyTyPe-E>, :60expires_in, :scope("A B") },
            { :token<MyToKeN-5>, :type<MyTyPe-E>, :refresh-token(Str:U), :expires(now + 60), :scope(<A B>.Set) }),
           ({ :access_token<MyToKeN-6>, :token_type<MyTyPe-F>, :60expires_in, :refresh_token<MyReFrEsHtOkEn-3>,
              :scope("A B") },
            { :token<MyToKeN-6>, :type<MyTyPe-F>, :refresh-token<MyReFrEsHtOkEn-3>, :expires(now+60),
              :scope(<A B>.Set) }),
           ({ :access_token<MyToKeN-7>, :token_type<MyTyPe-G>, :refresh_token<MyReFrEsHtOkEn-4>, :scope("A B") },
            { :token<MyToKeN-7>, :type<MyTyPe-G>, :refresh-token<MyReFrEsHtOkEn-4>, :expires(Instant:U),
              :scope(<A B>.Set) }),
           ;

for @test -> (%response, %expected) {
    subtest "Response " ~ ++$ ~ ".", {
        plan 8;
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

        is $authorization.status, Kept, "Authorization is done";
        my $r = $authorization.result;
        isa-ok $r, Ej::OAuth::Authorization:D, "Authorization is good type";

        cmp-ok $r.token, '~~', %expected<token>, "Token is ok";
        cmp-ok $r.type, '~~', %expected<type>, "Type is ok";
        cmp-ok $r.refresh-token, '~~', %expected<refresh-token>, "Refresh-token is ok";
        with %expected<expires> {
            is-approx $r.expires, now + 60, 3, "Expiration is true";
        } else {
            cmp-ok $r.expires, '~~', %expected<expires>, "Expiration is ok";
        }
        cmp-ok $r.scope, '~~', %expected<scope>, "Scope is ok";
    }
}

done-testing;
