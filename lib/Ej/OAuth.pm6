unit class Ej::OAuth;

use Cro::HTTP::Server;
use Cro::HTTP::Router;
use Cro::HTTP::Client;
use URL;
use URI::Encode;

class Authorization {
    ...
}

sub todo(*@args) {
    warn "TODO: ", @args».gist.flat;
}


has Enumeration:U $.scopes is required;

has Str:D $.authorize-uri is required;
has Str:D $.access-token-uri is required;

has Str:D $.client-id is required;
has Str:D $.client-secret is required;
has Str:D $.redirect-uri is required;

#| Configuration for generate security state
has $.state-generator-validity = 60 * 10;
has Str:D @.state-generator-chars = |('a' .. 'z'), |('A' .. 'Z'), |('0' .. '9');
has UInt:D $.state-generator-len = 30;

#| Store emitted Authorization state
has Authorization:D %!states-authorization{Str:D};

#| A supply emit a Hash for each callback request, if not specified, this class create a server with Cro.
#|
#| for valid callback need emit %(:$state!, :$code!)
#| for error callback need emit %(:$state!, :$error!, :$error_description, :$error_uri)
has Supply $.callback;

#| $.callback-* information for start webserver for callback, if a information isn't specified, it's get
#| from parsing $.redirect-uri
has List $.callback-proto;
has List $.callback-path;
has UInt $.callback-port;
has Str $.callback-host;
has IO $.callback-ssl-key;
has IO $.callback-ssl-cert;
has Bool:D $.callback-only-local = True;

#| The service started if no $.callback specified
has Cro::Service $!callback-service;

#| Create a CRO web server with information in $!callback-* and return a Supply emit a hash with callback information
method !mini-webserver(--> Supply:D) {
    my $supplier = Supplier.new;
    my URL:D $url .= new($!redirect-uri);
    say $url;
    my $callback-proto = $!callback-proto // $url.scheme // "http";
    my $port = $!callback-port // $url.port // ($callback-proto eq 'https' ?? 443 !! 80);
    my @callback-path = $!callback-path // $url.path // ();
    my $host = $!callback-host // $url.hostname // 'localhost';

    if $callback-proto eq 'https' {
        die "HTTPS is not yet supported";
    }
    if $callback-proto eq 'https' and (not $!callback-ssl-cert.defined or not $!callback-ssl-key.defined) {
        die "Unable to start https server without ssl key or without ssl certificate";
    }
    unless @callback-path.join('/') eq 'redirect' {
        die "Unable to start a web server with path different of '/redirect', sorry, maybe in future version";
    }

    my $application = route {
        if $!callback-only-local {
            before {
                forbidden unless .connection.peer-host eq '127.0.0.1' | '::1';
            }
        }
        get -> "redirect", :$state is required, :$code is required {
            $supplier.emit(%(:$state, :$code));
            content 'text/plain', 'Your authentication is now processed by the application, thanks';
        }
        get -> "redirect", :$state is required, :$error is required, :$error_description, :$error_uri {
            $supplier.emit(%(:$state, :$error, :$error_description, :$error_uri));
            content 'text/plain', 'Your authentication is in error, this is now processed by the application, thanks';
        }
    }
    $!callback-service = Cro::HTTP::Server.new(
            :$host, :$port, :$application,
            );
    $!callback-service.start;
    return $supplier.Supply;
}

method generate-state(--> Str:D) {
    @!state-generator-chars.roll($!state-generator-len).join;
}

submethod TWEAK {
    $!callback //= self!mini-webserver;

    multi ttt(:$state!, :$code!) {
        if %!states-authorization{$state}:exists {
            %!states-authorization{$state}.receive-code(:$state, :$code);
        } else {
            die "Receive code ($code) for unknown state ($state)";
        }
    }
    multi ttt(:$state!, :$error!, :$error_description, :$error_uri) {
        if %!states-authorization{$state}:exists {
            %!states-authorization{$state}.receive-error(:$state, :$error, :$error_description, :$error_uri);
        } else {
            die "Receive error ($error) for unknown state ($state)";
        }
    }

    $!callback.tap: -> %_ { ttt |%_ };

}

method authorize(::?CLASS:D: :@scope, *%args --> Authorization) {
    for @scope {
        unless $_ ~~ $!scopes {
            die "Scope { $_.raku } is out of the scopes for this OAuth object"
        }
    }
    my $state = ('a' .. 'z').roll(50).join;
    say @scope, " ", %args, ' ', $state;
    my $auth = Authorization.new:
            :parent(self),
            :@scope,
            ;
    $auth;
}

method remove-state(::?CLASS:D: Authorization:D $auth) {
    %!states-authorization{$auth._state}:delete;
}
method add-state(::?CLASS:D: Authorization:D $auth) {
    if %!states-authorization{$auth._state}:exists {
        die "Unable to add 2 authorization with same state, sorry";
    }
    %!states-authorization{$auth._state} = $auth;
}


class Authorization {
    has Ej::OAuth:D $.parent is required;
    has @.scope is required;

    has Lock:D $!lock .= new;
    has Str:D $!state = $!parent.generate-state;
    has Instant:D $!state-validity = now + $!parent.state-generator-validity;

    has Supplier:D $!token-changed .= new;

    submethod TWEAK {
        self!save-state;
    }

    method token-changed(::?CLASS:D: --> Supply:D) {
        $!token-changed.Supply
    }
    method url(--> Str:D) {
        my URL $url .= new: $!parent.authorize-uri;
        $url .= add-query:
                :response_type<code>,
                :client_id(uri_encode_component $!parent.client-id),
                :redirect_uri(uri_encode_component $!parent.redirect-uri),
                :scope(uri_encode_component @!scope.join(' ')),
                :$!state,
                ;
        $url.Str;
    }

    method receive-code(:$state!, :$code!) {if self.test-state($state, :invalid) {
        todo "New valide code receive : $code";
        my $resp = await Cro::HTTP::Client.post:
                $!parent.access-token-uri,
                #                    user-agent => "Raku OAuth API client Ej::OAuth (v0.0.1)",
                :content-type<application/x-www-form-urlencoded>,
                :headers([:accept<application/json>]),
                body => %(
                    :grant_type<authorization_code>,
                    :$code,
                    :client_id($!parent.client-id),
                    :client_secret($!parent.client-secret),
                    :redirect_uri($!parent.redirect-uri)
                ),
                ;
        with $resp.body.result -> (:access_token($token), :token_type($type), *%args) {
            $!token-changed.emit(%(:$token, :$type, err => Nil));
            with %args<expires_in> { ... }
            with %args<refresh_token> { ... }
#            with %args<scope> { ... }
        }
    } else {
        todo "change error to X::Ej::OAuth";
        $!token-changed.emit(%(token => Nil, type => Nil, err => "Receive token with invalid token"));
    }}
    method receive-error(:$state!, :$error!, :$error_description, :$error_uri) {
        if self.test-state($state, :invalid) {
            todo "Error: ";
        } else {
            todo "Warn invalid code receive";
        }
    }

    method !invalid-state {
        $!lock.protect: {
            $!parent.remove-state: self;
            $!state-validity = Instant.from-posix(0);
        }
    }

    method !save-state {
        $!lock.protect: {
            $!parent.add-state: self;
        }
    }

    method _state {
        $!state
    }
    method test-state(Str:D $code, Bool:D :$invalid --> Bool:D) {
        my Bool $ret;
        $!lock.protect: {
            $ret = $!state-validity > now and $!state eq $code;
            if $invalid {
                self!invalid-state;
            }
        }
        return $ret;
    }
    method !renew-state(--> Str:D) {
        self!invalid-state;

        my $code = $!parent.generate-state;
        $!lock.protect: {
            $!state = $code;
            $!state-validity = now + $!parent.state-generator-validity;
            self!save-state;
        }
        $code;
    }

}
