<?php
/**
 * validate-fw.php — authoritative PCRE check for the firewall feed.
 *
 * The plugin matches rules with PHP's preg_match, so the feed must be validated
 * with PHP, not just Python. This reads the built NDJSON and confirms every
 * pattern compiles under the SAME engine and delimiter the plugin uses
 * (FirewallRules::wrap => '#...#' with '#' escaped). Exits non-zero on the
 * first invalid pattern so CI fails before an unusable feed is published.
 *
 * Usage:  php validate-fw.php firewall-rules.ndjson
 */

if ( $argc < 2 ) {
	fwrite( STDERR, "usage: php validate-fw.php <firewall-rules.ndjson>\n" );
	exit( 2 );
}
$path = $argv[1];
$fh   = fopen( $path, 'rb' );
if ( ! $fh ) {
	fwrite( STDERR, "cannot open {$path}\n" );
	exit( 2 );
}

$rules = 0;
$bad   = 0;
$line  = 0;
while ( false !== ( $raw = fgets( $fh ) ) ) {
	$line++;
	$raw = trim( $raw );
	if ( '' === $raw ) {
		continue;
	}
	$o = json_decode( $raw, true );
	if ( ! is_array( $o ) || empty( $o['pattern'] ) ) {
		continue; // meta or non-rule line
	}
	$rules++;
	$re = '#' . str_replace( '#', '\\#', (string) $o['pattern'] ) . '#';
	if ( false === @preg_match( $re, '' ) ) {
		$bad++;
		fwrite( STDERR, sprintf( "line %d: rule %s has an invalid PCRE pattern: %s\n", $line, $o['id'] ?? '?', $o['pattern'] ) );
	}
}
fclose( $fh );

if ( 0 === $rules ) {
	fwrite( STDERR, "no rules found in {$path}\n" );
	exit( 1 );
}
if ( $bad > 0 ) {
	fwrite( STDERR, "{$bad} invalid pattern(s) of {$rules}.\n" );
	exit( 1 );
}
fwrite( STDOUT, "OK: {$rules} rules, all patterns valid PCRE.\n" );
exit( 0 );
