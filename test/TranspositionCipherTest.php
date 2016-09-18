<?php

use GGG\TranspositionCipher as TranspoCipher;

class TranspositionCipherTest extends \PHPUnit_Framework_TestCase
{

	private $params;
	private $format;
	private $expected_ciphered_text;
	private $expected_deciphered_text;
	
	public function __construct()
	{
		$this->params = [
			'text' => 'This is a sentence in English.',
	 		'key' => 'wizard'
		];
		$this->format = 0;
		// format: 0 = non-formatted result
		// format: 1 = formatted result
		$this->expected_ciphered_text = 'ITNSIEELSEEHTANNSNIIHSCG';
	}
	
	public function testEncode()
	{
		$transpositionCipher = new TranspoCipher;
		$actual_ciphered_text = $transpositionCipher->encrypt( $this->params, $this->format );
		$this->assertSame( $expected_ciphered_text, $actual_ciphered_text );
	}

}
