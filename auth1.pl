#!/Applications/PATRIC.app/runtime/bin/perl

use v5.10;
use HTTP::Server::PSGI;
use Plack::Request;
use Data::Dumper;
use strict;
use LWP::UserAgent;
use JSON::XS;
use URI;

$Data::Dumper::Sortkeys = 1;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

#
# GLUU

my $metadata_url = "https://gluu.olson.pri/.well-known/openid-configuration";
my $client_id = "ad10c32c-730d-4452-800a-adac978f8e16";
my $client_secret = "kMJ6H8rm0AVD5utIWNmNO5fTEL5fbtQyOGBBpxBp";
my $redirect_uri = "http://localhost:8080";
my $scopes = "openid all";

# Okta

#my $metadata_url = "https://dev-786278.okta.com/oauth2/default/.well-known/oauth-authorization-server";
#my $client_id = "0oarwz4agckCGsVyI4x6";
#my $client_secret = "OK5sNCkEPjoc-vlN_i3uBFgeJiXLouy6LYt94oQo";
#my $redirect_uri = "http://localhost:8080/authorization-code/callback";
#my $scopes = "openid";

my $ua  = LWP::UserAgent->new();
$ua->requests_redirectable([]);
    
my $md = OAuthMetadata->new($ua, $metadata_url);

my $auth_url = $md->authorization_endpoint;

say $auth_url;

#
# Set up server
#

my $http_server = HTTP::Server::PSGI->new(
    port => 8080,
    );

	 

#
# Make auth request
#

my $sent_state = "PID$$";

my $uri = URI->new($auth_url);

#my $response_type = 'id_token';
my $response_type = 'code';
my @nonce;
if ($response_type eq 'id_token')
{
    @nonce = (nonce => "NONCE");
}

$uri->query_form([response_type => $response_type,
		  @nonce,
		  client_id => $client_id,
		  redirect_uri => $redirect_uri,
#		  response_mode => 'form_post',
		  state => $sent_state,
		  scope => $scopes,
		 ]);
say $uri;

my $res = $ua->get($uri);

#
# Verify we have redirect, and issue it. Await the request on the server.
#

if ($res->code != 302)
{
    die "Did not get redirect\n" . $res->content;
}

my $redirect_url = $res->headers->{'location'};
say "Redirect $redirect_url";

system("open", $redirect_url);
#system("open", "-a", "Google Chrome", $redirect_url);

my($code, $session_id, $session_state, $state, $error);

$http_server->run(sub {
    my($env) = @_;

    $env->{'psgix.harakiri.commit'} = 1;

    my $req = Plack::Request->new($env);

    my $q = $req->query_parameters();

    $code = $q->{code};
    $session_id = $q->{session_id};
    $session_state = $q->{session_state};
    $state = $q->{state};
    $error = $q->{error};
    
    return [200,
	    ['Content-type' => 'text/plain'],
	    [Dumper($env, $q)],
	];
		  });

print "Got state=$state $sent_state\n";

if ($error)
{
    die $error;
}
       

#
# We now may request an access token.
#

my $res = $ua->post($md->token_endpoint(),
		    [grant_type => 'authorization_code',
		     code => $code,
		     redirect_uri => $redirect_uri,
		     client_id => $client_id,
		     client_secret => $client_secret,
		    ]);

if (!$res->is_success())
{
    die "access token request failed " . $res->content;
}

my $data = $res->content;
my $doc = decode_json($data);

my $token = $doc->{access_token};
say $token;

my $uri = URI->new($md->introspection_endpoint());
$uri->query_form([token => $token,
		  client_id => $client_id,
		  client_secret => $client_secret]);
my $res = $ua->post($md->introspection_endpoint(),
		    [token => $token,
		  client_id => $client_id,
		     client_secret => $client_secret]);
if ($res->is_success)
{
    print $res->content;
}
else
{
    die "Failed: $uri " . $res->content;
}

package OAuthMetadata;
use strict;
use JSON::XS;
use Data::Dumper;


sub new
{
    my($class, $ua, $url) = @_;

    my $res = $ua->get($url);
    my $data = decode_json($res->content);

    my $self = {
	ua => $ua,
	url => $url,
	data => $data
    };
    return bless $self, $class;
}

sub authorization_endpoint
{
    my($self) = @_;
    return $self->{data}->{authorization_endpoint};
}

sub token_endpoint
{
    my($self) = @_;
    return $self->{data}->{token_endpoint};
}

sub introspection_endpoint
{
    my($self) = @_;
    return $self->{data}->{introspection_endpoint};
}


