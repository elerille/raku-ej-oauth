use Cro::HTTP::Server;
use Cro::HTTP::Router;
use Cro::HTTP::Client;
use URL;
use URI::Encode;

use X::Ej::OAuth;

unit class Ej::OAuth is export(:class);

enum ClientType is export(:enum) <Confidential Public>;
enum ClientAuthMethod is export(:enum) <None Basic Body>;

class Authorization is export(:class) {
    has Str:D $.token is required;
    has Str:D $.type is required;
    has $.expires;
    has Set:D $.scope is required;
    has Set:D $.scope-asked is required;


    method raku(::?CLASS:D:) {
        "{ ::?CLASS.^name }.new("
        ~ ":token(???), "
        ~ (:$!type, :$!expires, :$!scope, :$!scope-asked)».raku.join(', ')
        ~ ")";
    }
}

class AuthorizationPromise is Promise {
    has Str:D $.url is required;
    has Set:D $.scope is required;
}


#| List (or enum) of scope can by use for OAuth
has $.scope is required where List:D | Enumeration:U | Array:D;

#| Endpoint to redirect User Agent for request authorization
has Str:D $.endpoint-authorization is required;

#| Endpoint for request a token
has Str:D $.endpoint-token is required;

#| Endpoint for Authorization Server redirect User Agent after authenticate it
has Str $.endpoint-redirection;

has Str:D $.client-id is required;
has Str:D $.client-secret is required;
has Ej::OAuth::ClientType:D $.client-type = Ej::OAuth::ClientType::Confidential;

has Ej::OAuth::ClientAuthMethod:D $.client-auth-method = Body;

has Cro::HTTP::Client:D $!client .= new: :content-type<application/x-www-form-urlencoded>,
                                         :user-agent("{ $?DISTRIBUTION.meta<name> } ({ $?DISTRIBUTION.meta<ver> })"),
                                         :headers([:accept<application/json>]),
                                         |do if $!client-auth-method ~~ ClientAuthMethod::Basic {
                                             auth => { :username($!client-id), :password($!client-secret) }
                                         },
                                         ;

has Str:D @.state-generator = lazy gather do { loop { take ('a' .. 'z').roll(25).join } };

has Ej::OAuth::AuthorizationPromise:D %!emitted-promise{Str:D};

method raku(::?CLASS:D:) {
    "{ ::?CLASS.^name }.new("
    ~ (:$!scope, :$!endpoint-authorization, :$!endpoint-token, :$!endpoint-redirection, :$!client-id)».raku.join(', ')
    ~ ", :client-secret(???), "
    ~ (:$!client-type, :$!client-auth-method, :@!state-generator)».raku.join(', ')
    ~ ")";
}

method test-scope(::?CLASS:D:
                  $elem
        --> Bool:D)
{
    if $!scope ~~ Enumeration {
        $elem.defined and $elem ~~ $!scope
    } else {
        $elem.defined and $elem ∈ $!scope
    }
}

method authorization(::?CLASS:D:
                     Ej::OAuth::ClientType:D $client-type = $!client-type,
                     :@scope where { self.test-scope($_.all) },
        --> Ej::OAuth::AuthorizationPromise:D
                     )
{
    my $scope = @scope.Set;
    my URL:D $url .= new: $!endpoint-authorization;
    my Str:D $state = @!state-generator.shift;
    my Str:D $response_type = do given $client-type {
        when Confidential { "code" }
        when Public { "token" }
        default { die "Unsupported client-type ($client-type), please open an issue on Ej::Oauth github" }
    };
    my %query = :$response_type,
                :client_id($!client-id),
#                :scope($scope.keys.join(' ')),
                :$state;
    %query<redirect_uri> = $!endpoint-redirection with $!endpoint-redirection;
    %query<scope> = $scope.keys.join(' ') if $scope;
    for %query.values -> $v is rw {
        $v = uri_encode_component $v;
    }
    $url.=add-query: |%query;

    my Ej::OAuth::AuthorizationPromise $promise .= new: :url($url.Str), :$scope;

    %!emitted-promise{$state} = $promise;

    return $promise;
}

#| Die if $state is false or isn't present. In other case, the AuthorizationPromise is broke
method authorization-response(::?CLASS:D:
                              Str:D :$state!,
                              *%args
        --> Nil)
{
    if %!emitted-promise{$state}:exists {
        my Ej::OAuth::AuthorizationPromise:D $promise = %!emitted-promise{$state};
        %!emitted-promise{$state}:delete;
        self.validate-authorization-promise: $promise, |%args;
        CATCH {
            when Exception {
                $promise.break: $_;
            }
        }
    } else {
        die "Receive response with unknown state, please log this error";
    }
}

#| if response_type eq 'code' in authorization request
multi method validate-authorization-promise(::?CLASS:D:
                                            Ej::OAuth::AuthorizationPromise:D $promise,
                                            Str:D :$code!
        --> Nil) is implementation-detail
{
    my %result = self.access-token-request('authorization_code', :$code);
    samewith $promise, |%result;
}
#| if response_type eq 'token' in authorization request
multi method validate-authorization-promise(::?CLASS:D:
                                            Ej::OAuth::AuthorizationPromise:D $promise,
                                            Str:D :$access_token!,
                                            Str:D :$token_type!,
                                            :$expires_in,
                                            Str :$scope = ""
        --> Nil) is implementation-detail
{
    my $expires;
    with $expires_in {
        $expires = now + $expires_in;
    }
    $promise.keep: Ej::OAuth::Authorization.new: :token($access_token),
                                                 :type($token_type),
                                                 :$expires,
                                                 :scope($scope.split(' ', :skip-empty).Set),
                                                 :scope-asked($promise.scope),
                                                 ;
}
multi method validate-authorization-promise(::?CLASS:D:
                                            Ej::OAuth::AuthorizationPromise:D $promise,
                                            Str:D :$error!,
                                            Str :$error_description,
                                            Str :$error_uri
        --> Nil) is implementation-detail
{
    $promise.break: X::Ej::OAuth.new: :$error, :$error_description, :$error_uri;
}



multi method access-token-request(::?CLASS:D:
                                  'refresh_token',
                                  Str:D :$refresh_token!,
                                  :@scope where { self.test-scope($_.all) },
        --> Hash
                                  ) is implementation-detail
{
    samewith :grant-type<refresh_token>, :$refresh_token, :scope(@scope.join(' '));
}
multi method access-token-request(::?CLASS:D:
                                  'client_credentials',
                                  :@scope where { self.test-scope($_.all) },
        --> Hash
                                  ) is implementation-detail
{
    samewith :grant-type<client_credentials>, :scope(@scope.join(' '));
}
multi method access-token-request(::?CLASS:D:
                                  'password',
                                  :@scope where { self.test-scope($_.all) },
                                  Str:D :$username!,
                                  Str:D :$password!,
        --> Hash
                                  ) is implementation-detail
{
    samewith :grant-type<password>, :scope(@scope.join(' ')), :$username, :$password;
}
multi method access-token-request(::?CLASS:D:
                                  'authorization_code',
                                  Str:D :$code!,
        --> Hash
                                  ) is implementation-detail
{
    samewith :grant-type<authorization_code>, :$code, :redirect_uri($!endpoint-redirection), :client_id($!client-id);
}
multi method access-token-request(::?CLASS:D:
                                  Str:D :$grant-type!,
                                  *%body is copy
        --> Hash
                                  ) is implementation-detail
{
    given $!client-auth-method {
        when Ej::OAuth::ClientAuthMethod::Body {
            %body<client_id> = $!client-id;
            %body<client_secret> = $!client-secret;
        }
        when Ej::OAuth::ClientAuthMethod::None {}
        when Ej::OAuth::ClientAuthMethod::Basic {}
        default {
            die "Unsupported client-auth-method ($!client-auth-method), please open an issue on Ej::Oauth github"
        }
    }
    %body<grant_type> = $grant-type;

    my $resp = await $!client.post: $!endpoint-token,
                                    :%body,
                                    ;

    return await $resp.body;

    #        ->
    # §5.1 & §5.2

    #        multi method access-token-response(:$access_token!, :$token_type!, :$expires_in, :$refresh_token, :$scope) {...}
    #        multi method access-token-response(Str:D :$error!, Str :$error_description, Str :$error_uri) {
    #            $error (elem)
    ##             <invalid_request unauthorized_client access_denied unsupported_response_type invalid_scope server_error temporarily_unavailable *>;
    #            <invalid_request invalid_client invalid_grant unauthorized_client unsupported_grant_type invalid_scope>
    #            ...
    #        }

}

#
##| Return (Str:D $url, Promise[Authorization]:D)method authorize(::?CLASS:D: :@scope, *%args) {
#for @scope{
#unless $_ ~~ $!scopes {
#    die "Scope { $_.raku
#
#    }
#is out of the scopes for this OAuthobject"
#
#}
#}my $generated-state = self.generate-state;
#
#my $p = Promise.new;
#multi ttt(:$code!) {
#    todo "New valide code receive : $code";
#    todo "POST to $!access-token-uri";
#    my $resp = await Cro::HTTP::Client.post:
#            $!access-token-uri,
#            #user-agent => "Raku OAuth API client Ej::OAuth (v0.0.1)",
#            :content-type<application/x-www-form-urlencoded>,
#            :headers([:accept<application/json>]),
#            body => %(
#                :grant_type<authorization_code>,
#                :$code,
#                :client_id($!client-id),
#                :client_secret($!client-secret),
#                :redirect_uri($!redirect-uri)
#            ),
#            ;
#    with $resp.body.result -> (:access_token($token), :token_type($token-type), *%args) {
#        with %args<expires_in> { ... }
#        with %args<refresh_token> { ... }
#        #            with %args<scope> { ... }
#
#        my $auth = Authorization.new:
#                :parent(self),
#                :@scope,
#                :$token,
#                :$token-type;
#        $p.keep($auth);
#    } else {
#        $p.break("Fail to receive token");
#    }
#
#}
#multi ttt(:$error!, :$error_description, :$error_uri) {
#    $p.break: %(:$error, :$error_description, :$error_uri);
#}
#
#self.add-state: $generated-state, -> :$state!, *%args {
#    if $state ne $generated-state { $p.break("State verification failed") }
#    else { ttt |%args }
#}
#
#return self.url($generated-state, @scope), $p;
#}
#
#multi method remove-state(::?CLASS:D: Str:D $state) {
#    %!states-authorization{$state}:delete;
#}
#multi method remove-state(::?CLASS:D: Authorization:D $auth) {
#    self.remove-state: $auth._state;
#}
#multi method add-state(::?CLASS:D: Str:D $state, &callable) {
#    if %!states-authorization{$state}:exists {
#        die "Unable to add 2 authorization with same state, sorry";
#    }
#    %!states-authorization{$state} = &callable;
#}
#multi method add-state(::?CLASS:D: Authorization:D $auth) {
#    ...;
#    if %!states-authorization{$auth._state}:exists {
#        die "Unable to add 2 authorization with same state, sorry";
#    }
#    %!states-authorization{$auth._state} = $auth;
#}
#
#method url($state, @scope --> Str:D) {
#    my URL $url .= new: $!authorize-uri;
#    $url .= add-query:
#            :response_type<code>,
#            :client_id(uri_encode_component $!client-id),
#            :redirect_uri(uri_encode_component $!redirect-uri),
#            :scope(uri_encode_component @scope.join(' ')),
#            :$state,
#            ;
#    $url.Str;
#}
#
#class Authorization {
#has Ej::OAuth:D $.parent is required;
#has @.scope is required;
#
#has Lock:D $!lock .= new;
#has Str $!state;
#has Instant:D $!state-validity = Instant.from-posix(0);
##now + $!parent.state-generator-validity;
#
#has Str:D $.token is required;
#has Str:D $.token-type is required;
#has Supplier:D $!token-changed .= new;
#
#method token-changed(::?CLASS:D: --> Supply:D) {
#    $!token-changed.Supply
#}
#
#method receive-code(:$state!, :$code!) {...
##        if self.test-state($state, :invalid) {
##            #        todo "New valide code receive : $code";
##            #        my $resp = await Cro::HTTP::Client.post:
##            #                $!parent.access-token-uri,
##            #                #                    user-agent => "Raku OAuth API client Ej::OAuth (v0.0.1)",
##            #                :content-type<application/x-www-form-urlencoded>,
##            #                :headers([:accept<application/json>]),
##            #                body => %(
##            #                    :grant_type<authorization_code>,
##            #                    :$code,
##            #                    :client_id($!parent.client-id),
##            #                    :client_secret($!parent.client-secret),
##            #                    :redirect_uri($!parent.redirect-uri)
##            #                ),
##            #                ;
##            #        with $resp.body.result -> (:access_token($token), :token_type($type), *%args) {
##            #            $!token-changed.emit(%(:$token, :$type, err => Nil));
##            #            with %args<expires_in> { ... }
##            #            with %args<refresh_token> { ... }
##            #            #            with %args<scope> { ... }
##            #        }
##        } else {
##            todo "change error to X::Ej::OAuth";
##            $!token-changed.emit(%(token => Nil, type => Nil, err => "Receive token with invalid token"));
##        }}
#method receive-error(:$state!, :$error!, :$error_description, :$error_uri) {
#...
##        if self.test-state($state, :invalid) {
##            todo "Error: ";
##        } else {
##            todo "Warn invalid code receive";
##        }}
#
#method !invalid-state {
#    $!lock.protect: {
#        $!parent.remove-state: self;
#        $!state-validity = Instant.from-posix(0);
#    }
#}
#
#method !save-state {
#    $!lock.protect: {
#        $!parent.add-state: self;
#    }
#}
#
#method _state {
#    $!state
#}
#method test-state(Str:D $code, Bool:D :$invalid --> Bool:D) {...
##        my Bool $ret;
##        $!lock.protect: {
##            $ret = $!state-validity > now and $!state eq $code;
##            if $invalid {
##                self!invalid-state;
##            }
##        }
##        return $ret;}
#method !renew-state(--> Str:D) {
#    self!invalid-state;
#
#    my $code = $!parent.generate-state;
#    $!lock.protect: {
#        $!state = $code;
#        $!state-validity = now + $!parent.state-generator-validity;
#        self!save-state;
#    }
#    $code;
#}}
#
#
#
#=begin pod
#OAuth 2.0
#RFR 6749
#
#Client Identifier = String with undefined size
#Access Token = String with undefined size
#
#
#HTTP Basic with Authorization Server for get Token
# - 2.3.1 §1
# - Annexe B
#OR
#Body with :$client_id!, :$client_secret!
#
#endpoint = {
# - :authorization<> # Server side # HTTPS!
# - :token<>, # Server side # HTTPS! POST!
# - :redirection<>, # Server side # Do not execute third-party scripts
#}
#=end pod
