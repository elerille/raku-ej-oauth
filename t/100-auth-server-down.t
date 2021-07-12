use Test;
use Test::Util::ServerPort;
use URL;

use Ej::OAuth :ALL;

plan 2;

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

$oauth.authorization-response(:$state, :code($expected-code));

is $authorization.status, Broken, "Broken authorization promise when auth serveur is down";
is $authorization.cause.message, "connection refused", "Good message when auth serveur is down";

done-testing;
