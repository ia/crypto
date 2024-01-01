#!/usr/bin/env perl


# must have
use strict;
use warnings;
use diagnostics;


# include external modules
use Time::HiRes;
use MIME::Base64;


# use debug output?
our $use_debug = 1;

# english letters frequency
our @freq_eng = split(//,"etaoinshrdlcumwfgypbvkjxqz");
	# top:    etaoin
	# middle: shrdlcumwfgypb
	# bottom: vkjxqz
	# sources:
	#  - http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies
	#  - http://en.wikipedia.org/wiki/Letter_frequency

# russian letters frequency
our @freq_rus = split(//,"оеаинтсрвлкмдпуяыьгзбчйхжшюцщэфъё");
	# top:    оеаинтср
	# middle: влкмдпуяыьгзбчйхж
	# bottom: шюцщэфъё
	# sources:
	#  - http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/russian-letter-frequencies
	#  - http://ru.wikipedia.org/wiki/Частотность


### helper routine section ###


sub base2plain
{
	return decode_base64($_[0]);
}


sub plain2base
{
	return encode_base64($_[0]);
}


sub base2hex
{
	my $hex = unpack('H*', decode_base64($_[0]));
}


sub hex2base
{
	my $hex = pack "H*", $_[0];
	return encode_base64($hex);
}


sub hex2plain
{
	my $str = pack "H*", $_[0];
	$str =~ s/[^[:print:]]/?/g;
	return $str;
}


sub plain2hex
{
	return unpack "H*", $_[0];
}


sub str2xor # ('aaaa', 'bbbb') => aaaa ^ bbbb
{
	my $str1 = $_[0];
	my $str2 = $_[1];
	my @str1 = split(//,$str1);
	my @str2 = split(//,$str2);
	my $l = length($str1);
	my $r = "";
	
	if ($l != length($str2) {
		# TODO: padding?
		return $r;
	}
	# TODO: use something like:
	#@r = map { $array1[$_] + $array2[$_] } 0..$#array1;
	for (my $e = 0; $e < $l; $e++) {
		printf "%x ^ %x = %x\n", hex $str1[$e], hex $str2[$e], hex $str1[$e] ^ hex $str2[$e] unless not $use_debug;
		$r .= sprintf "%x", hex $str1[$e] ^ hex $str2[$e];
	}
	
	return $r;
}


sub str2xorline # ('a', 'bbbb') => aaaa ^ bbbb
{
	my $chr = $_[0];
	my @str = split(//,$_[1]);
	my $l = length($_[1]);
	my $r = "";
	# TODO: use map
	for (my $e = 0; $e < $l; $e++) {
		printf "%x ^ %x = %x\n", hex $str[$e], hex $chr, hex $str[$e] ^ hex $chr unless not $use_debug;
		$r .= sprintf "%x", hex $str[$e] ^ hex $chr;
	}
	return $r;
}


sub getnchar # ('a', 'aabbaa') => 4
{
	my $ch = $_[0];
	my $str = $_[1];
	my $r = ($str =~ s/$ch/$ch/gi);
	return $r eq "" ? 0 : $r;
}


sub getnchars # ('aaabbc') => a,3,b,2,c,1,d,0,..
{
	my $str = $_[0];
	my @chars = ("");
	my @dict = ('a'..'z');
	my $step = 0;
	foreach my $ch (@dict) {
		printf "%s = %d\n", $ch, getnchar($ch, $str) unless not $use_debug;
		$chars[(ord $ch) - 97 + $step] = $ch;
		$chars[((ord $ch) - 97) + $step + 1] = getnchar($ch, $str);
		$step++;
	}
	return @chars
}


sub getsortnchars # ('aabccc') => c,a,b,d,..
{
	my @eng = split(//,"etaoinshrdlcumwfgypbvkjxqz");
	my %chars = getnchars(lc $_[0]);
	my @keys = sort { ($chars{$b} <=> $chars{$a}) || ($a cmp $b) } keys %chars;
	
	printf "\nKEYS {\n";
	print @keys;
	printf "\n";
	my $i = 0;
	foreach my $key ( @keys ) {
		printf "%s == %d | %s\n", $key, $chars{$key}, $eng[$i] unless not $use_debug;
		$i++;
	}
	printf "\nKEYS }\n";
	
	my @eng_top = @eng[0..5];
	my @eng_bot = @eng[((length @eng)-8)..((length @eng)-3)];
	
	my $loop = 0;
	$i = 0;
	my $improve = 1;
	if ($improve) {
		while ($loop <= 26*26) {
			$i = 0;
			foreach my $key ( @keys[0..13] ) {
				printf "%s == %d | %s/%s = %s/%s | %s\n", $key, $chars{$key}, $keys[0], $chars{$keys[0]}, $keys[1], $chars{$keys[1]}, $eng[$i] unless not $use_debug;
				my $j = $i + 1;
				if (($chars{$keys[$i]} == $chars{$keys[$j]}) and ($keys[$j] ~~ @eng_top) and (not ($keys[$i] ~~ @eng_top))) {
					($keys[$i], $keys[$j]) = ($keys[$j], $keys[$i]);
				}
				$i++;
			}
			printf "\n\n" unless not $use_debug;
			$loop++;
		}
		
		print "====================== KEYS KEYS KEYS: " . "@keys" . "\n";
		
		$loop = 0;
		while ($loop <= 26*26) {
			printf "BOTTOM LOOP\n";
			$i = (length @keys)-4;
			foreach my $key (reverse @keys[0..12]) {
				printf "BOTTOM LOOP IN 1\n";
				
				my $j = $i + 1;
				printf "BOTTOM LOOP IN 2\n";
				printf "BOTTOM: %s == %d | %s/%s = %s/%s | %s\n", $key, $chars{$key}, $keys[$i], $chars{$keys[0]}, $keys[1], $chars{$keys[1]}, $eng[$i] unless not $use_debug == 0;
				printf "BOTTOM LOOP IN 3\n";
				if (($chars{$keys[$i]} == $chars{$keys[$j]}) and ($keys[$j] ~~ @eng_bot) and (not ($keys[$i] ~~ @eng_bot))) {
					($keys[$i], $keys[$j]) = ($keys[$j], $keys[$i]);
				}
				$i++;
			}
			$loop++;
		}
	}
	print "KEYS: " . "@keys" . "\n";
	print "KEYS REV: ";
	print reverse @keys;
	print "\n";
	return @keys;
}


sub getfreq # wrapper
{
	return getsortnchars($_[0]);
}


sub getscore # ('a large string with english-like text') => 6/3
{
	my $str = $_[0];
	my $score = 0;
	my @eng = split(//,"etaoinshrdlcumwfgypbvkjxqz");
	my @frq = getfreq($str);
	print "FREQ:\n";
	print @frq;
	print "\n";
	my @frq_top = @frq[0..5];
	print "FREQ TOP:\n";
	print @frq_top;
	print "\n";
	my @frq_bottom = @frq[((length @frq)-8)..((length @frq)-3)];
	print "FREQ BOT:\n";
	print @frq_bottom;
	print "\n";
	foreach my $e (@eng[0..5]) {
		if ($e ~~ @frq_top) {
			printf "%s+\n", $e;
			$score += 1;
		}
	}
	foreach my $e (@eng[((length @eng)-8)..((length @eng)-3)]) {
		printf "Be == %s\n", $e;
		if ($e ~~ @frq_bottom) {
			$score += 1;
			printf "%s+\n", $e;
		}
	}
	printf "RESULT = %d\n", $score;
	return $score;
}


sub brutexor
{
	my $chiphertext = $_[0];
	my @brute = ("a".."z");
}


sub gethammingdist
{
    return ($_[0] ^ $_[1]) =~ tr/\001-\255//;
}


##############################


### tasks section ###


# convert hex to base and vice versa
sub task0
{
	printf "\n==== ==== ==== ==== task0 { ==== ==== ==== ====\n";
	my $hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	my $base_output = hex2base($hex_input);
	printf "hex input = %s\nbase output = %s\n", $hex_input, $base_output;
	
	printf "decoding ...\n";
	my $base_input = $base_output;
	my $hex_output = base2hex($base_input);
	
	printf "base input = %s\nhex output = %s\n", $base_input, $hex_output;
	
	printf "task0: ";
	if ($hex_input ne $hex_output) {
		printf "FAIL\n";
	} else {
		printf "PASS\n";
	}
	printf "\n==== ==== ==== ==== task0 } ==== ==== ==== ====\n";
	return 0;
}


# string1 xor string2
sub task1
{
	printf "\n==== ==== ==== ==== task1 { ==== ==== ==== ====\n";
	my $str1 = "1c0111001f010100061a024b53535009181c";
	my $str2 = "686974207468652062756c6c277320657965";
	my $strr = "746865206b696420646f6e277420706c6179";
	
	printf "s1 = $str1\n";
	printf "s2 = $str2\n";
	
	my $r = str2xor($str1, $str2);
	printf "r == $r\n";
	
	printf "task1: ";
	if ($r ne $strr) {
		printf "FAIL\n";
	} else {
		printf "PASS\n";
	}
	printf "\n==== ==== ==== ==== task1 } ==== ==== ==== ====\n";
	return 0;
}


# decode xored string
sub task2
{
	printf "\n==== ==== ==== ==== task2 { ==== ==== ==== ====\n";
	my $ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	
	printf "\n==== ==== ==== ==== task2 } ==== ==== ==== ====\n";
	return 0;
}


##############################


### main section ###


printf "\n==== ==== ==== ==== main { ==== ==== ==== ====\n";
my $ts = [Time::HiRes::gettimeofday];


task0;
task1;


#my $c = count_char('a', "aabaAc");
#printf "c == %d\n", $c;

#my %chars = count_chars("ayayaybybycybyzyz");

##my @chars = getsortnchars_ng("ayayaybybycybyzyz");

#print "y == " . @chars{"y"} . ".\n";

##print @chars;

print "\ntest score:";
print getscore('a large string with english-like text');
print "\n";
#print getscore("Sy l nlx sr pyyacao l ylwj eiswi upar lulsxrj isr sxrjsxwjr, ia esmm rwctjsxsza sj wmpramh, lxo txmarr jia aqsoaxwa sr pqaceiamnsxu, ia esmm caytra jp famsaqa sj. Sy, px jia pjiac ilxo, ia sr pyyacao rpnajisxu eiswi lyypcor l calrpx ypc lwjsxu sx lwwpcolxwa jp isr sxrjsxwjr, ia esmm lwwabj sj aqax px jia rmsuijarj aqsoaxwa. Jia pcsusx py nhjir sr agbmlsxao sx jisr elh. -Facjclxo Ctrramm");
print "ABCSCORE\n";


exit;


#my @keys = sort { $chars{$b} <=> $chars{$a} } keys %chars;

#foreach my $key ( @keys ) {
#	printf "%-20s %6d\n", $key, $chars{$key};
#}


print base2plain "YWJjZAo=";
print plain2base "abcd\n";
print "getfreq:\n";
print getfreq("abcd");
print "\n";
print getfreq("Alan Mathison Turing was a British mathematician");
print "\n";
print getscore("Alan Mathison Turing was a British mathematician");
print "\ntest score:";
print getscore('a large string with english-like text');
print "\n";


print plain2hex("ab");
print hex2plain("616215");
print "\n";
print str2xorline("A", "BBBB");
print "\n";


my $time = Time::HiRes::tv_interval ( $ts, [Time::HiRes::gettimeofday]);
printf "time: %.6f\n", $time;
printf "\n==== ==== ==== ==== main } ==== ==== ==== ====\n";


exit;


