requires 'Carp';
requires 'parent';
requires 'Module::Runtime';
requires 'Digest::SHA';
requires 'Exporter';
requires 'JSON';
requires 'MIME::Base64', '3.13';
requires 'perl', '5.008001';

on build => sub {
    requires 'Test::Mock::Guard', '0.07';
    requires 'Test::More', '0.98';
    requires 'Test::Requires', '0.06';
};
