use Test;
use URL;
use Cro::HTTP::Server;
use Cro::HTTP::Router;

use Ej::OAuth :ALL;

plan 9;

#my Int:D $server-port = get-unused-port;
#my Int:D $client-port = get-unused-port;
my Str:D $endpoint-authorization = "http://localhost/authorization";
my Str:D $endpoint-token = "http://localhost/token";
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

is $oauth.client-secret, $expected-client-secret, "client-secret is realy stored";
unlike $oauth.gist, /$expected-client-secret/, "client-secret doesn't show in OAuth.gist";
unlike $oauth.Str, /$expected-client-secret/, "client-secret doesn't show in OAuth.Str";
unlike $oauth.raku, /$expected-client-secret/, "client-secret doesn't show in OAuth.raku";

my $r = Ej::OAuth::Authorization.new: :token($expected-token), :type<bearer>, :scope(Set.new), :scope-asked(Set.new);

is $r.token, $expected-token, "token is realy stored";
unlike $r.gist, /$expected-token/, "token doesn't show in Authorization.gist";
unlike $r.Str, /$expected-token/, "token doesn't show in Authorization.Str";
unlike $r.raku, /$expected-token/, "token doesn't show in Authorization.raku";


flunk "TODO: Test if refresh-token doesn't show in *.gist, *.Str and *.raku";


done-testing;
