unit class X::Ej::OAuth is Exception;


enum Type <AccessDenied InvalidClient InvalidGrant InvalidRequest InvalidScope Other ServerError
           TemporarilyUnavailable UnauthorizedClient UnsupportedGrantType UnsupportedResponseType>;

has Type:D $type is required;
has Str $description;
has Str $uri;

method new(::?CLASS:U:
           Str:D :$error!,
           Str :$error_description,
           Str :$error_uri
           )
{
    my Type $type = do given $error {
        when 'access_denied' { X::Ej::OAuth::Type::AccessDenied }
        when 'invalid_client' { X::Ej::OAuth::Type::InvalidClient }
        when 'invalid_grant' { X::Ej::OAuth::Type::InvalidGrant }
        when 'invalid_request' { X::Ej::OAuth::Type::InvalidRequest }
        when 'invalid_scope' { X::Ej::OAuth::Type::InvalidScope }
        when 'server_error' { X::Ej::OAuth::Type::ServerError }
        when 'temporarily_unavailable' { X::Ej::OAuth::Type::TemporarilyUnavailable }
        when 'unauthorized_client' { X::Ej::OAuth::Type::UnauthorizedClient }
        when 'unsupported_grant_type' { X::Ej::OAuth::Type::UnsupportedGrantType }
        when 'unsupported_response_type' { X::Ej::OAuth::Type::UnsupportedResponseType }
        default { X::Ej::OAuth::Type::Other }
    }
    self.bless: :$type, :description($error_description), :uri($error_uri);
}
