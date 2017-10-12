use strict;
use warnings;
use t::Util;

use Test::More;
use Test::Requires 'Crypt::PK::ECC';

my $pk256 = Crypt::PK::ECC->new()->generate_key("nistp256");
test_encode_decode(
    desc  => 'ES256',
    input => {
        claims     => { foo => 'bar' },
        secret     => $pk256->export_key_pem("private"),
        public_key => $pk256->export_key_pem("public"),
        algorithm  => 'ES256',
    },
);

my $bad_pk256 = Crypt::PK::ECC->new()->generate_key("nistp256");
test_encode_decode(
    desc  => 'ES256',
    input => {
        claims     => { foo => 'bar' },
        secret     => $pk256->export_key_pem("private"),
        public_key => $bad_pk256->export_key_pem("public"),
        algorithm  => 'ES256',
    },
    expects_exception => "Invalid signature"
);

my $pk384 = Crypt::PK::ECC->new()->generate_key("nistp384");
test_encode_decode(
    desc  => 'ES384',
    input => {
        claims     => { foo => 'bar' },
        secret     => $pk384->export_key_pem("private"),
        public_key => $pk384->export_key_pem("public"),
        algorithm  => 'ES384',
    },
);

my $bad_pk384 = Crypt::PK::ECC->new()->generate_key("nistp384");
test_encode_decode(
    desc  => 'ES384',
    input => {
        claims     => { foo => 'bar' },
        secret     => $pk384->export_key_pem("private"),
        public_key => $bad_pk384->export_key_pem("public"),
        algorithm  => 'ES384',
    },
    expects_exception => "Invalid signature"
);

my $pk521 = Crypt::PK::ECC->new()->generate_key("nistp521");
test_encode_decode(
    desc  => 'ES512',
    input => {
        claims     => { foo => 'bar' },
        secret     => $pk521->export_key_pem("private"),
        public_key => $pk521->export_key_pem("public"),
        algorithm  => 'ES512',
    },
);

my $bad_pk521 = Crypt::PK::ECC->new()->generate_key("nistp521");
test_encode_decode(
    desc  => 'ES512',
    input => {
        claims     => { foo => 'bar' },
        secret     => $pk521->export_key_pem("private"),
        public_key => $bad_pk521->export_key_pem("public"),
        algorithm  => 'ES512',
    },
    expects_exception => "Invalid signature"
);

done_testing;
