# Test RFC6749 section 4.1.1 (https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)

use Test;
use Test::Util::ServerPort;
use URL;
use Cro::HTTP::Server;
use Cro::HTTP::Router;
use URI::Encode;

use Ej::OAuth :ALL;

plan 2;

#my Int:D $server-port = get-unused-port;
#my Int:D $client-port = get-unused-port;
my Str:D $endpoint-authorization = "http://localhost:8080/authorization";
my Str:D $endpoint-token = "http://localhost:8080/token";
my Str:D $endpoint-redirection = "http://localhost/redirect";
my Str:D $expected-client-id = "MyClIeNtId";
my Str:D $expected-client-secret = "MyClIeNtSeCrEt";
my Str:D $expected-code = "MyCoDe";
my Str:D $expected-token = "MyToKeN";

enum MyScope <A B C>;
subtest "Simple URI to load for the user is correct", {
    plan 6;

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

    my URL:D $url .= new: $authorization.url;

    is URL.new(|$url.Hash, query => {}).Str,
       $endpoint-authorization,
       "Redirect to a correct URI base";

    is-deeply $url.query.keys.Set,
              <client_id redirect_uri response_type scope state>.Set,
              "Query contains only good field";

    is $url.query<client_id>,
       $expected-client-id,
       "Client id isn't modified and is transmitted";

    is uri_decode_component($url.query<redirect_uri>),
       $endpoint-redirection,
       "Redirect URI isn't modified and is transmitted";

    is $url.query<response_type>,
       "code",
       "Response type is 'code'";

    is-deeply uri_decode_component($url.query<scope>).split(' ').Set,
              ("A", "B").Set,
              "Scope is corect";
}
subtest "Simple URI to load for the user is correct", {
    plan 8;

    $endpoint-authorization ~= "?test=A&retest=qwe";

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

    my URL:D $url .= new: $authorization.url;

    is URL.new(|$url.Hash, query => {}).Str,
       URL.new(|URL.new($endpoint-authorization).Hash, query => {}).Str,
       "Redirect to a correct URI base";

    is-deeply $url.query.keys.Set,
              <client_id redirect_uri response_type scope state test retest>.Set,
              "Query contains only good field";

    is $url.query<client_id>,
       $expected-client-id,
       "Client id isn't modified and is transmitted";

    is uri_decode_component($url.query<redirect_uri>),
       $endpoint-redirection,
       "Redirect URI isn't modified and is transmitted";

    is $url.query<response_type>,
       "code",
       "Response type is 'code'";

    is-deeply uri_decode_component($url.query<scope>).split(' ').Set,
              ("A", "B").Set,
              "Scope is corect";

    is $url.query<test>, "A", "test params is transmitted";
    is $url.query<retest>, "qwe", "retest params is transmitted";
}

done-testing;
