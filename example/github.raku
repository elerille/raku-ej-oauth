#!/usr/bin/raku

use Ej::OAuth :ALL;

use Cro::HTTP::Server;
use Cro::HTTP::Router;
use Cro::HTTP::Client;

# A selection of real GitHub scope
enum GitHubScope <repo security_events gist notifications user delete_repo workflow>;

my $client-id = %*ENV<GITHUB_CLIENT_ID> // die "missing github client-id";# "4ed3bc92f0f94f7507f2";
my $client-secret = %*ENV<GITHUB_CLIENT_SECRET> // die "missing github client-secret";# "b28ed87663f0cff01ee3240d4695fbd946cbf8a2";
my $port = 8181;

# Create an object OAuth with all parameter for interact with authorization server
my OAuth:D $oauth .= new: :scope(GitHubScope),
                          :endpoint-authorization<https://github.com/login/oauth/authorize>,
                          :endpoint-token<https://github.com/login/oauth/access_token>,
                          :endpoint-redirection("http://127.0.0.1:$port/redirect"),
                          :$client-id,
                          :$client-secret,
                          client-type => Confidential,
                          ;

# Start a web application listing on `endpoint-redirection` and transmit request to $oauth
# This can be integrate to your application
my $application = route {
    get -> 'redirect', :%params {
        $oauth.authorization-response(|%params);
        # Security Note on this page don't send a third-party script
        content "text/plain", "Your authentication is now doing in the application";
    }
}
my Cro::Service $service = Cro::HTTP::Server.new: :host<127.0.0.1>,
                                                  :$port,
                                                  :$application;
$service.start;

say $service;

# Create an authorization request and ask the user to load authentication page
my Ej::OAuth::AuthorizationPromise $promise = $oauth.authorization: :scope(GitHubScope::repo,);
say "Please load page : ", $promise.url;

# Wait for the authorization
#
# if authorization fail, the promise is brokt, but this don't have timeout
my Ej::OAuth::Authorization $auth = await $promise;

# Verify the type of the token
unless $auth.type eq "bearer" {
    die "Unsupported token type";
}

# Create a HTTP client use the token
my Cro::HTTP::Client $http-client .= new: :base-uri<https://api.github.com/>,
                                          :auth(:bearer($auth.token));

$auth.tap:
        -> $_ {
            # When new token, replace the client by a new one
            if .type ne "bearer" {
                $auth.quit: "Unsupported token type";
            } else {
                $http-client .= new: :base-uri<https://api.github.com/>,
                                     :auth(:bearer(.token));
            }
        },
        done => -> {
            # Authentication is ended by call $auth.done
            $http-client = Cro::HTTP::Client;
        },
        quit => -> $ex {
            # An error is occurred when renew token
            $http-client = Cro::HTTP::Client;
            $ex.throw;
        }

# Make your software

# User is log-off
$auth.done;

# Here $http-client is undefined

say "OK";
