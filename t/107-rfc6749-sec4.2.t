# Test RFC6749 section 4.2.1 (https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.1)
# For RFC6749 section 4.2.2 see file t/105-rfc6749-sec4.1.2.1.t

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

my MyScope:D @scopeA = A, B;
my MyScope:D @scopeB = ();

subtest "standard request", {
    plan 6;
    my $authorization = $oauth.authorization: Public,
                                              :scope(A, B);
    my URL:D $url .= new: $authorization.url;

    is URL.new(|$url.Hash, query => {}).Str,
       $endpoint-authorization,
       "Redirect to a correct URI base";

    is-deeply $url.query.keys.Set, <client_id redirect_uri response_type scope state>.Set,
              "Query contains only good field";
    is $url.query<response_type>, "token", "Response type is 'code'";
    is $url.query<client_id>, $expected-client-id, "Client id isn't modified and is transmitted";
    is uri_decode_component($url.query<redirect_uri>), $endpoint-redirection,
       "Redirect URI isn't modified and transmitted";
    is-deeply uri_decode_component($url.query<scope>).split(' ', :skip-empty).Set, <A B>.Set, "Scope is corect";
}
{
    my $authorization = $oauth.authorization: Public;
    my URL:D $url .= new: $authorization.url;
    nok $url.query<scope>:exists, "Query not contains scope if not necessary";
}
{
    my OAuth:D $oauth2 .= new: :scope(MyScope),
                               :$endpoint-authorization,
                               :$endpoint-token,
                               client-id => $expected-client-id,
                               client-secret => $expected-client-secret,
                               ;
    my $authorization = $oauth2.authorization: Public,
                                               :scope(A, B);
    my $state = URL.new($authorization.url).query<state>;
    my URL:D $url .= new: $authorization.url;

    nok $url.query<redirect_uri>:exists, "Query not contains redirect_uri if not necessary";
}


dies-ok { $oauth.authorization-response: :sccess_token($expected-token), :token_type<bearer> },
        "Response without state";

subtest "Response without access_token", {
    plan 2;
    my $authorization = $oauth.authorization: Public,
                                              :scope(A, B);
    my $state = URL.new($authorization.url).query<state>;
    lives-ok { $oauth.authorization-response: :$state, :token_type<bearer> },
             "Response not emit an error";
    is $authorization.status, Broken, "Authorization is brokt";
}

subtest "Response without token_type", {
    plan 2;
    my $authorization = $oauth.authorization: Public,
                                              :scope(A, B);
    my $state = URL.new($authorization.url).query<state>;
    lives-ok { $oauth.authorization-response: :$state, :access_token($expected-token) },
             "Response not emit an error";
    is $authorization.status, Broken, "Authorization is brokt";
}

subtest "Response without access_token, token_type", {
    plan 2;
    my $authorization = $oauth.authorization: Public,
                                              :scope(A, B);
    my $state = URL.new($authorization.url).query<state>;
    lives-ok { $oauth.authorization-response: :$state },
             "Response not emit an error";
    is $authorization.status, Broken, "Authorization is brokt";
}

subtest "Minimal valid response", {
    plan 3;
    my $authorization = $oauth.authorization: Public,
                                              :scope(A,);
    my $state = URL.new($authorization.url).query<state>;
    lives-ok { $oauth.authorization-response: :$state, :access_token($expected-token), :token_type<bearer> },
             "Response not emit an error";
    is $authorization.status, Kept, "Authorization is brokt";
    my $r = $authorization.result;
    is-deeply $r,
              Ej::OAuth::Authorization.new(:token($expected-token), :type("bearer"), :expires(Any), :scope(set()),
                                           :scope-asked(A.Set)),
              "Authorization is valid";
}

subtest "Response with expires_in", {
    plan 3;
    my $authorization = $oauth.authorization: Public,
                                              :scope(A,);
    my $state = URL.new($authorization.url).query<state>;
    lives-ok {
                 $oauth.authorization-response: :$state, :access_token($expected-token), :token_type<bearer>,
                                                :expires_in<60>
             },
             "Response not emit an error";
    is $authorization.status, Kept, "Authorization is brokt";
    my $r = $authorization.result;
    is-approx $r.expires, now + 60, 3, "Expiration is true";
}

subtest "Response with other scope", {
    plan 4;
    my $authorization = $oauth.authorization: Public,
                                              :scope(A,);
    my $state = URL.new($authorization.url).query<state>;
    lives-ok {
                 $oauth.authorization-response: :$state, :access_token($expected-token), :token_type<bearer>,
                                                :scope<B>
             },
             "Response not emit an error";
    is $authorization.status, Kept, "Authorization is brokt";
    my $r = $authorization.result;
    is $r.scope, <B>.Set, "Scope receive is stored";
    is $r.scope-asked, <A>.Set, "Scope asked is stored";
}

done-testing;
