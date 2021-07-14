
## Example

 - [Github connexion](example/github.raku)

## Grant method
### Supported
 - Authorization code grant (`OAuth.new(:client-type(Confidential)).authorization`)
 - Implicit grant (for public client) (`OAuth.new(:client-type(Public)).authorization`)
 - Resource owner password credentials grant (`$oauth.authorization: :$username, :$password`)
 - Client credentials grant (`$oauth.authorization: :client`)

### Extension grant
For the RFC, the protocol can be extend by adding grant, but this library isn't now supported it.
If you use an extension, can open an issue or a pull request.


## TODO
 - Move todo in TODO.md
 - Add check when receive a response if this response have the same grant_type as the request.
 - Add test authorization named
