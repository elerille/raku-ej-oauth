# Test RFC6749 section 4.1.2.1 (https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
# Test RFC6749 section 4.2.2 (https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2)

use Test;
use Test::Util::ServerPort;
use URL;
use Cro::HTTP::Server;
use Cro::HTTP::Router;
use URI::Encode;

use Ej::OAuth :ALL;

plan 17;

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
                          client-type => Confidential,
                          ;

my MyScope:D @scope = A, B;

my $authorization = $oauth.authorization: :@scope;

my $state = URL.new($authorization.url).query<state>;
subtest "without state", {
    plan 2;
    dies-ok { $oauth.authorization-response(:error<invalid_request>) }, "Receive error without state is an error";
    is $authorization.status, Planned, "Authorization isn't now valided";
}
subtest "with false state", {
    plan 3;
    my $error-state = "NoNeVaLiDsTaTe";

    isnt $state, $error-state, "error-state (used for test) isn't equals to real state";
    if $state eq $error-state {
        skip 'Can\'t test with $error-state eq $state';
    } else {
        dies-ok { $oauth.authorization-response(:state($error-state), :error<invalid_request>) },
                "Receive error with false state is an error";
    }
    is $authorization.status, Planned, "Authorization isn't now valided";
}

my @test =
        ({ :error<invalid_request>, },
         { :type(X::Ej::OAuth::Type::InvalidRequest), :description(Str), :uri(Str) }),
        ({ :error<unauthorized_client>, },
         { :type(X::Ej::OAuth::Type::UnauthorizedClient), :description(Str), :uri(Str) }),
        ({ :error<access_denied>, },
         { :type(X::Ej::OAuth::Type::AccessDenied), :description(Str), :uri(Str) }),
        ({ :error<unsupported_response_type>, },
         { :type(X::Ej::OAuth::Type::UnsupportedResponseType), :description(Str), :uri(Str) }),
        ({ :error<invalid_scope>, },
         { :type(X::Ej::OAuth::Type::InvalidScope), :description(Str), :uri(Str) }),
        ({ :error<server_error>, },
         { :type(X::Ej::OAuth::Type::ServerError), :description(Str), :uri(Str) }),
        ({ :error<temporarily_unavailable>, },
         { :type(X::Ej::OAuth::Type::TemporarilyUnavailable), :description(Str), :uri(Str) }),
        ({ :error<access_denied>, :error_description("Ma description perso") },
         { :type(X::Ej::OAuth::Type::AccessDenied), :description("Ma description perso"), :uri(Str) }),
        ({ :error<access_denied>, :error_uri("http://example.com/jkdshf") },
         { :type(X::Ej::OAuth::Type::AccessDenied), :description(Str), :uri("http://example.com/jkdshf") }),
        ({ :error<access_denied>, :error_description("Ma description perso"), :error_uri("http://example.com/jkdshf") },
         { :type(X::Ej::OAuth::Type::AccessDenied), :description("Ma description perso"),
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

for @test -> (%test, %expected) {
    subtest "Test receive error { %test.gist }", {
        plan 6;
        my $authorization = $oauth.authorization: :@scope;
        my $state = URL.new($authorization.url).query<state>;

        $oauth.authorization-response(:$state, |%test);
        is $authorization.status, Broken, "Authorization is brokt";
        my $r = $authorization.cause;
        isa-ok $r, X::Ej::OAuth:D, "Cause is X::Ej::OAuth";
        is-deeply $r, X::Ej::OAuth.new(|%test), "Error is apparently valid";
        is $r.type, %expected<type>, "Error type is ok";
        is $r.description, %expected<description>, "Error description is ok";
        is $r.uri, %expected<uri>, "Error URI is ok";
    }
}

#subtest "with good state", {
#    plan 3;
#    my $mock-server = Cro::HTTP::Server.new:
#            :host<localhost>, :port($server-port),
#            application => route {
#                post -> *@path, | {
#                    diag "Verify no other process/people send a http request to the test server";
#                    flunk "Request to a non-ok page (POST /{ @path.join('/') })";
#                }
#                get -> *@path, | {
#                    diag "Verify no other process/people send a http request to the test server";
#                    flunk "Request to a non-ok page (GET /{ @path.join('/') })";
#                }
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
#    #    is $r.token, $expected-token, "token is valid";
#    #    is $r.type, "bearer", "token type is 'bearer'";
#    #    nok $r.expires.defined, "No expires is defined";
#    #    is $r.scope.elems, 0, "No scope is retourned by server";
#    #    is-deeply $r.scope-asked, @scope.Set, "Scope asked is preserved";
#}

done-testing;
