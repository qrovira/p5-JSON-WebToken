package JSON::WebToken::Crypt::EC;

use strict;
use warnings;
use parent 'JSON::WebToken::Crypt';

use Crypt::PK::ECC ();

my %ALGORITHM2HASHFUNCS = (
    ES256 => 'SHA256',
    ES384 => 'SHA384',
    ES512 => 'SHA512',
);

sub sign {
    my ($class, $algorithm, $message, $key) = @_;
    my $hash = $ALGORITHM2HASHFUNCS{ $algorithm };

    my $private_key = Crypt::PK::ECC->new(\$key);
    return $private_key->sign_message($message, $hash);
}

sub verify {
    my ($class, $algorithm, $message, $key, $signature) = @_;
    my $hash = $ALGORITHM2HASHFUNCS{ $algorithm };

    my $public_key = Crypt::PK::ECC->new(\$key);
    return $public_key->verify_message($signature, $message, $hash) ? 1 : 0;
}

1;
__END__
