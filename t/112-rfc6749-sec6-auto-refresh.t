# Test RFC6749 section 5.2 (https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)

use Test;
use Test::Util::ServerPort;
use URL;
use Cro::HTTP::Server;
use Cro::HTTP::Router;
use URI::Encode;

use Ej::OAuth :ALL;

plan 5;

my $expires_in = 0.1;
my $second-expires_in = 60;

my Int:D $server-port = get-unused-port;
#my Int:D $client-port = get-unused-port;
my Str:D $endpoint-authorization = "http://localhost:$server-port/authorization";
my Str:D $endpoint-token = "http://localhost:$server-port/token";
my Str:D $endpoint-redirection = "http://localhost/redirect";
my Str:D $expected-client-id = "MyClIeNtId";
my Str:D $expected-client-secret = "MyClIeNtSeCrEt";
my Str:D $expected-code = "MyCoDe";
my Str:D $expected-token = "MyToKeN";
my Str:D $expected-second-token = "MySeCoNdToKeN";
my Str:D $expected-refresh-token = "MyReFrEsHtoKeN";
my Str:D $expected-second-refresh-token = "MySeCoNdReFrEsHtoKeN";
my Str:D $expected-username = "MyUsErNaMe";
my Str:D $expected-password = "MyPaSsWoRd";

$Ej::OAuth::Authorization::expire-margin = 0;

enum MyScope <A B C>;

my OAuth:D $oauth .= new: :scope(MyScope),
                          :$endpoint-authorization,
                          :$endpoint-token,
                          :$endpoint-redirection,
                          client-id => $expected-client-id,
                          client-secret => $expected-client-secret,
                          client-type => Confidential,
                          ;

sub server-response(%initial-response, %refresh-response) {
    Cro::HTTP::Server.new:
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
                        content "application/json", %initial-response;
                    }, -> (:$grant_type, :$refresh_token, :$client_id, :$client_secret, :$scope) {
                        subtest "Renew sent to authorization server", {
                            plan 4;
                            is $grant_type, 'refresh_token', "grant_type is refresh_token";
                            is $refresh_token, $expected-refresh-token, "good refresh token receive";
                            is $client_id, $expected-client-id, "good client_id receive";
                            is $client_secret, $expected-client-secret, "good client_secret receive";
                        }
                        content "application/json", %refresh-response;
                    }, -> %_ {
                        flunk "Request with unknown data " ~ %_.gist;
                    }
                }
            };
}

my %initial-response = :access_token($expected-token),
                       :token_type<bearer>,
                       :refresh_token($expected-refresh-token),
                       :$expires_in,
                       ;

subtest "Auto update authorization", {
    plan 7;

    # Server → send new token
    my $mock-server = server-response %initial-response, { :access_token($expected-second-token),
                                                           :token_type<bearer>,
                                                           :expires_in($second-expires_in) }
    $mock-server.start;

    my $authorization = $oauth.authorization: :scope(A,);
    my $state = URL.new($authorization.url).query<state>;

    # 1 test in server
    $oauth.authorization-response(:$state, code => $expected-code);



    is $authorization.status, Kept, "Authorization is kept";
    my $r = $authorization.result;
    is $r.token, $expected-token, "Token is ok";
    is $r.refresh-token, $expected-refresh-token, "Refresh-token is ok";

    # 1 test in server
    sleep 2*$expires_in;

    is $r.token, $expected-second-token, "Second Token is ok";
    is $r.refresh-token, $expected-refresh-token, "Refresh-token is ok";

    $r.done;
    $mock-server.stop;
}

subtest "Event update authorization 1", {
    plan 9;

    # Server → send new token
    my $mock-server = server-response %initial-response, { :access_token($expected-second-token),
                                                           :token_type<bearer>,
                                                           :expires_in($second-expires_in),
                                                           :refresh_token($expected-refresh-token) }
    $mock-server.start;

    my $authorization = $oauth.authorization: :scope(A,);
    my $state = URL.new($authorization.url).query<state>;

    # 1 test in server
    $oauth.authorization-response(:$state, code => $expected-code);

    is $authorization.status, Kept, "Authorization is kept";
    my $r = $authorization.result;
    is $r.token, $expected-token, "Token is ok";
    is $r.refresh-token, $expected-refresh-token, "Refresh-token is ok";
    my $tap = $r.tap: -> Authorization $auth {
        is $auth.token, $expected-second-token, "Second Token is ok";
        is $auth.refresh-token, $expected-refresh-token, "Refresh-token is ok";
    },
            done => -> { flunk "End of authorization" },
            quit => -> $ex { flunk "Error on renew token $ex" },
            ;

    # 1 test in server
    sleep 2*$expires_in;

    is $r.token, $expected-second-token, "Second Token is ok";
    is $r.refresh-token, $expected-refresh-token, "Refresh-token is ok";

    $tap.close;
    $r.done;
    $mock-server.stop;
}

subtest "Event update authorization 2", {
    plan 9;

    # Server → send new token and new refresh token
    my $mock-server = server-response %initial-response, { :access_token($expected-second-token),
                                                           :token_type<bearer>,
                                                           :expires_in($second-expires_in),
                                                           :refresh_token($expected-second-refresh-token) }
    $mock-server.start;

    my $authorization = $oauth.authorization: :scope(A,);
    my $state = URL.new($authorization.url).query<state>;

    # 1 test in server
    $oauth.authorization-response(:$state, code => $expected-code);

    is $authorization.status, Kept, "Authorization is kept";
    my $r = $authorization.result;
    is $r.token, $expected-token, "Token is ok";
    is $r.refresh-token, $expected-refresh-token, "Refresh-token is ok";
    my $tap = $r.tap: -> Authorization $auth {
        is $auth.token, $expected-second-token, "Second Token is ok";
        is $auth.refresh-token, $expected-second-refresh-token, "Second Refresh-token is ok";
    },
            done => -> { flunk "End of authorization" },
            quit => -> $ex { flunk "Error on renew token" },
            ;

    # 1 test in server
    sleep 2*$expires_in;

    is $r.token, $expected-second-token, "Second Token is ok";
    is $r.refresh-token, $expected-second-refresh-token, "Second Refresh-token is ok";

    $tap.close;
    $r.done;
    $mock-server.stop;
}

subtest "Event end authorization", {
    # Server → Flunk for all
    plan 8;
    my $authorization = $oauth.authorization: :scope(A,);
    my $state = URL.new($authorization.url).query<state>;

    {
        my $mock-server = server-response %initial-response, {}
        $mock-server.start;

        $oauth.authorization-response(:$state, code => $expected-code);
        # 1 test in server

        $mock-server.stop;
    }

    is $authorization.status, Kept, "Authorization is kept";
    my $r = $authorization.result;
    is $r.token, $expected-token, "Token is ok";
    is $r.refresh-token, $expected-refresh-token, "Refresh-token is ok";
    my $tap = $r.tap: -> Authorization $auth { flunk "Renew authorization" },
            done => -> { pass "Authorization is terminated" },
            quit => -> $ex { flunk "Error on renew token" },
            ;
    $r.done;
    sleep 1;
    is $r.token, Str:U, "Token is removed";
    is $r.type, Str:U, "Type is removed";
    is $r.refresh-token, Str:U, "Refresh-token is removed";

    $tap.close;
    $r.done;
}

subtest "Event fail renew authorization", {
    plan 9;

    # Server → send error
    my $mock-server = server-response %initial-response, { :error<invalid_request> }
    $mock-server.start;

    my $authorization = $oauth.authorization: :scope(A,);
    my $state = URL.new($authorization.url).query<state>;

    $oauth.authorization-response(:$state, code => $expected-code);
    # 1 test in server

    is $authorization.status, Kept, "Authorization is kept";
    my $r = $authorization.result;
    is $r.token, $expected-token, "Token is ok";
    is $r.refresh-token, $expected-refresh-token, "Refresh-token is ok";
    my $tap = $r.tap: -> Authorization $auth { flunk "Renew authorization" },
            done => -> { flunk "End of authorization" },
            quit => -> $ex { pass "Error on renew token" },
            ;

    # 1 test in server
    sleep 2*$expires_in;

    is $r.token, Str:U, "Token is removed";
    is $r.type, Str:U, "Type is removed";
    is $r.refresh-token, Str:U, "Refresh-token is removed";

    $tap.close;
    $r.done;
    $mock-server.stop;
}

#
#subtest "standard request", {
#    plan 6;
#    my $authorization = $oauth.authorization: Public,
#                                              :scope(A, B);
#    my URL:D $url .= new: $authorization.url;
#
#    is URL.new(|$url.Hash, query => {}).Str,
#       $endpoint-authorization,
#       "Redirect to a correct URI base";
#
#    is-deeply $url.query.keys.Set, <client_id redirect_uri response_type scope state>.Set,
#              "Query contains only good field";
#    is $url.query<response_type>, "token", "Response type is 'code'";
#    is $url.query<client_id>, $expected-client-id, "Client id isn't modified and is transmitted";
#    is uri_decode_component($url.query<redirect_uri>), $endpoint-redirection,
#       "Redirect URI isn't modified and transmitted";
#    is-deeply uri_decode_component($url.query<scope>).split(' ', :skip-empty).Set, <A B>.Set, "Scope is corect";
#}
#{
#    my $authorization = $oauth.authorization: Public;
#    my URL:D $url .= new: $authorization.url;
#    nok $url.query<scope>:exists, "Query not contains scope if not necessary";
#}
#{
#    my OAuth:D $oauth2 .= new: :scope(MyScope),
#                               :$endpoint-authorization,
#                               :$endpoint-token,
#                               client-id => $expected-client-id,
#                               client-secret => $expected-client-secret,
#                               ;
#    my $authorization = $oauth2.authorization: Public,
#                                               :scope(A, B);
#    my $state = URL.new($authorization.url).query<state>;
#    my URL:D $url .= new: $authorization.url;
#
#    nok $url.query<redirect_uri>:exists, "Query not contains redirect_uri if not necessary";
#}
#
#
#dies-ok { $oauth.authorization-response: :sccess_token($expected-token), :token_type<bearer> },
#        "Response without state";
#
#subtest "Response without access_token", {
#    plan 2;
#    my $authorization = $oauth.authorization: Public,
#                                              :scope(A, B);
#    my $state = URL.new($authorization.url).query<state>;
#    lives-ok { $oauth.authorization-response: :$state, :token_type<bearer> },
#             "Response not emit an error";
#    is $authorization.status, Broken, "Authorization is brokt";
#}
#
#subtest "Response without token_type", {
#    plan 2;
#    my $authorization = $oauth.authorization: Public,
#                                              :scope(A, B);
#    my $state = URL.new($authorization.url).query<state>;
#    lives-ok { $oauth.authorization-response: :$state, :access_token($expected-token) },
#             "Response not emit an error";
#    is $authorization.status, Broken, "Authorization is brokt";
#}
#
#subtest "Response without access_token, token_type", {
#    plan 2;
#    my $authorization = $oauth.authorization: Public,
#                                              :scope(A, B);
#    my $state = URL.new($authorization.url).query<state>;
#    lives-ok { $oauth.authorization-response: :$state },
#             "Response not emit an error";
#    is $authorization.status, Broken, "Authorization is brokt";
#}
#
#subtest "Minimal valid response", {
#    plan 3;
#    my $authorization = $oauth.authorization: Public,
#                                              :scope(A,);
#    my $state = URL.new($authorization.url).query<state>;
#    lives-ok { $oauth.authorization-response: :$state, :access_token($expected-token), :token_type<bearer> },
#             "Response not emit an error";
#    is $authorization.status, Kept, "Authorization is brokt";
#    my $r = $authorization.result;
#    is-deeply $r,
#              Ej::OAuth::Authorization.new(:token($expected-token), :type("bearer"), :expires(Any), :scope(set()),
#                                           :scope-asked(A.Set)),
#              "Authorization is valid";
#}
#
#subtest "Response with expires_in", {
#    plan 3;
#    my $authorization = $oauth.authorization: Public,
#                                              :scope(A,);
#    my $state = URL.new($authorization.url).query<state>;
#    lives-ok {
#                 $oauth.authorization-response: :$state, :access_token($expected-token), :token_type<bearer>,
#                                                :expires_in<60>
#             },
#             "Response not emit an error";
#    is $authorization.status, Kept, "Authorization is brokt";
#    my $r = $authorization.result;
#    is-approx $r.expires, now + 60, 3, "Expiration is true";
#}
#
#subtest "Response with other scope", {
#    plan 4;
#    my $authorization = $oauth.authorization: Public,
#                                              :scope(A,);
#    my $state = URL.new($authorization.url).query<state>;
#    lives-ok {
#                 $oauth.authorization-response: :$state, :access_token($expected-token), :token_type<bearer>,
#                                                :scope<B>
#             },
#             "Response not emit an error";
#    is $authorization.status, Kept, "Authorization is brokt";
#    my $r = $authorization.result;
#    is $r.scope, <B>.Set, "Scope receive is stored";
#    is $r.scope-asked, <A>.Set, "Scope asked is stored";
#}
#
#
#my $authorization = $oauth.authorization: Public,
#                                          :scope(A, B);
#my $state = URL.new($authorization.url).query<state>;


#    my $mock-server = Cro::HTTP::Server.new:
#            :host<localhost>, :port($server-port),
#            application => route {
#                post -> *@path { flunk "Request to a non-ok page (POST /{ @path.join('/') })"; }
#                get -> *@path { flunk "Request to a non-ok page (GET /{ @path.join('/') })"; }
#                post -> 'token' {
#                    request-body -> (:$grant_type, :$code, :$redirect_uri, :$client_id,
#                                     :$client_secret) {
#                        subtest "Request sent to authorization server", {
#                            plan 5;
#                            is $grant_type, 'authorization_code', "grant_type is authorization_code";
#                            is $code, $expected-code, "good code receive";
#                            is $redirect_uri, $endpoint-redirection, "good redirect uri receive";
#                            is $client_id, $expected-client-id, "good client_id receive";
#                            is $client_secret, $expected-client-secret, "good client_secret receive";
#                        }
#                        content "application/json", {
#                            access_token => $expected-token,
#                            token_type => "bearer",
#                        };
#                    }
#                }
#            };
#    $mock-server.start;
#    $oauth.authorization-response(:$state, code => $expected-code);
#    $mock-server.stop;
#
#
#    is $authorization.status, Kept, "Authorization is done";
#    my $r = $authorization.result;
#    isa-ok $r, Ej::OAuth::Authorization:D, "Authorization is good type";
#
#    # For more see §5.1 and §5.2
#
#    #    is $r.token, $expected-token, "token is valid";
#    #    is $r.type, "bearer", "token type is 'bearer'";
#    #    nok $r.expires.defined, "No expires is defined";
#    #    is $r.scope.elems, 0, "No scope is retourned by server";
#    #    is-deeply $r.scope-asked, @scope.Set, "Scope asked is preserved";
done-testing;
