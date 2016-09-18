<?php

namecheap GGG;

class TranspositionCipher
{

  const LC_ALPHA = '/[a-z]/';
  const UC_ALPHA = '/[A-Z]/';
  const SING_DIG = '/[0-9]/';
  const MSC_SYMB = '/[\!\¡\?\¿\.\,\:\;\\\[\]\{\}\(\)\+\-\*\/\^\%\<\>\=\$\#\&\@\~\_\|]/';
  const BLNK_SPC = '/\s+?/';

  private $key;
  private $text;
  private $ciphertext;
  private $deciphertext;

  private $loca_alphas;
  private $upca_alphas;
  private $sing_digits;
  private $misc_symbls;

  private $loca_alphas_rev;
  private $upca_alphas_rev;
  private $sing_digits_rev;
  private $misc_symbls_rev;

  private $matrix;

  private static $instance = NULL;

  private function __construct()
  {
    $this->key = [
      'string' => [
        'original' => NULL,
        'modified' => NULL
      ],
      'length' => 0
    ];
    $this->text = [
      'string' => [
        'original' => NULL,
        'modified' => NULL
      ],
      'length' => 0
    ];
    $this->loca_alphas = range( 'a', 'z' );
    $this->upca_alphas = range( 'A', 'Z' );
    $this->sing_digits = range( 0, 9 );
    $this->misc_symbls = [ '!', '¡', '?', '¿', '.', ',', ':', ';', '\\', '[', ']', '{', '}', '(', ')', '+', '-', '*', '\/', '^', '%', '<', '>', '=', '\$', '#', '&', '@', '~', '_', '|' ];
    $this->loca_alphas_rev = array_flip( $this->loca_alphas );
    $this->upca_alphas_rev = array_flip( $this->upca_alphas );
    $this->sing_digits_rev = array_flip( $this->sing_digits );
    $this->misc_symbls_rev = array_flip( $this->misc_symbls );

    $this->matrix = [];
    $this->matrix['key_order'] = [];
    $this->matrix['cipher_table'] = [];
    $this->matrix['decipher_table'] = [];
    return $this;
  }

  private function formatStr( $s, $uc = 0 )
  {
    if( $uc === 1 || $uc === true )
    {
      $search = [
        static::MSC_SYMB,
        static::BLNK_SPC
      ];
      $replace = [
        '',
        ''
      ];
      $s = strtoupper( $s );
      return preg_replace( $search, $replace, $s );
    }
    return trim( $s );
  }

  private function setText( $text )
  {
    $this->text['string']['original'] = $text;
    $this->text['string']['modified'] = $this->formatStr( $text, true );
    $this->text['length'] = strlen( $this->formatStr( $text ) );
    return true;
  }

  private function setKey( $key )
  {
    $this->key['string']['original'] =  $key;
    $this->key['string']['modified'] = $this->formatStr( $key, true );
    $this->key['length'] = strlen( $this->formatStr( $key ) );
    return true;
  }

  private function prepEncryption( $t, $k )
  {
    if( $this->setText( $t ) )
    {
      if( $this->setKey( $k ) )
      {
        return true;
      }
    }
    return false;
  }

  private function prepDecryption( $t, $k )
  {
    if(! isset( $this->matrix['key_order'] ) )
    {
      $this->matrix['key_order'] = [];
    }
    if( $this->setText( $t ) )
    {
      if( $this->setKey( $k ) )
      {
        return true;
      }
    }
    return false;
  }

  private function calculateKeyOrder()
  {
    $key_array = str_split( $this->key['string']['modified'] );
    $char_order_array = [];
    foreach( $key_array as $i => $char )
    {
      if( preg_match( static::UC_ALPHA, $char ) )
      {
        $char_order_array[ $i ] = $this->upca_alphas_rev[ $char ];
      }
      if( preg_match( static::LC_ALPHA, $char ) )
      {
        $char_order_array[ $i ] = $this->loca_alphas_rev[ $char ];
      }
      if( preg_match( static::SING_DIG, $char ) )
      {
        $char_order_array[ $i ] = $this->sing_digits_rev[ $char ];
      }
      if( preg_match( static::MSC_SYMB, $char ) )
      {
        $char_order_array[ $i ] = $this->misc_symbls_rev[ $char ];
      }
    }
    if( natcasesort( $char_order_array ) )
    {
      $keys_by_order = [];
      $step = 0;
      foreach( $char_order_array as $i => $v )
      {
        $keys_by_order[ $step ] = $i + 1;
        $step++;
      }
      ksort( $keys_by_order, SORT_NUMERIC );
      $this->matrix['key_order'] = $keys_by_order;
      //echo '<script>alert(' . print_r($keys_by_order) . ');</script>';
      return true;
    }
    return false;
  }

  private function interpolateText()
  {
    $text_array = str_split( $this->text['string']['modified'] );
    $text_array_chunks = array_chunk( $text_array, $this->key['length'] );
    foreach( $text_array_chunks as $index => $chunk )
    {
      array_push( $this->matrix['cipher_table'], $chunk );
    }
    return true;
  }

  private function extrapolateText()
  {
    $text_array = str_split( $this->text['string']['modified'] );
    $text_array_chunks = array_chunk( $text_array, $this->text['length'] / $this->key['length'] );
    $order = array_flip( $this->matrix['cipher_table'] );
    ksort( $order );
    $order = array_flip( $order );
    asort( $order );
    $new_array = [];
    foreach( $order as $index => $true_index )
    {
      $new_array[ $index ] =  $text_array_chunks[ $index-1 ];
    }
    //ksort( $new_array );
    $arr = [];
    foreach( $new_array as $index => $arra )
    {
      foreach( $arra as $i => $val )
      {
        $arr[ $i ] = $val;
        $ix[] = $i;
      }
      $this->setColChar( $index, $arr );
      //print_r( $arr );
    }
    return true;
  }

  private function setColChar( $col_index, $data )
  {
    if(! is_array( $this->matrix['cipher_table'][ $col_index ] ) )
    {
      $this->matrix['cipher_table'][ $col_index ] = $data;
    }
    else
    {
      array_push( $this->matrix['cipher_table'][ $col_index ], $data );
    }
  }

  private function getColChar( $col_index )
  {
    var_dump( $this->matrix['cipher_table'] );
    $char = '';
    $col_index = $col_index + 1;
    foreach( $this->matrix['cipher_table'] as $i => $row )
    {
      
      //if( $i !== 0 )
      //{
     // foreach( $row as $ii => $char )
     // {
     //   if( $ii === $col_index )
     //   {
          $char .= $row[ $col_index ];
    //    }
    //  }
    }
    return $char;
  }

  private function formatCipher( $cipher )
  {
    $orig_text_chars = str_split( $this->text['string']['original'] );
    $tmp_cipher_chars = str_split( $cipher );
    $formatted_cipher = '';
    $offset = 0;
    foreach( $orig_text_chars as $i => $char )
    {
      if( in_array( $char, $this->upca_alphas ) )
      {
        $formatted_cipher .= strtoupper( $tmp_cipher_chars[ $offset ] );
        $offset++;
      }
      elseif( in_array( $char, $this->loca_alphas ) )
      {
        $formatted_cipher .= strtolower( $tmp_cipher_chars[ $offset ] );
        $offset++;
      }
      elseif( in_array( $char, $this->misc_symbls ) )
      {
        $formatted_cipher .= $char;
      }
      elseif( $char == ' ' )
      {
        $formatted_cipher .= ' ';
      }
      next( $orig_text_chars );
    }
    if( strlen( $formatted_cipher ) > 1 )
    {
      $this->ciphertext = $formatted_cipher;
      return true;
    }
    return false;
  }

  private function createCipher( $pretty )
  {
    $function_ran = false;
    $tmp_ciphertext = '';
    //$flipped_key_order = $this->matrix['key_order'];
    //ksort( $flipped_key_order );
    //foreach( $flipped_key_order as $i => $step )
    foreach( $this->matrix['key_order'] as $i => $step )
    {
      $tmp_ciphertext .= $this->getColChar( $i );
      $function_ran = true;
    }
    if( $function_ran === true && strlen( $tmp_ciphertext ) > 0 )
    {
      if( $pretty == 1 )
      {
        if( $this->formatCipher( $tmp_ciphertext ) )
        {
          return true;
        }
      }
      if( $pretty == 0 )
      {
        $this->ciphertext = $tmp_ciphertext;
        return true;
      }
    }
    return false;
  }

  private function flipMatrix( $sort = false )
  {
    $flipped = array_flip( $this->matrix['key_order'] );
    if( $sort === true || $sort === 1 )
    {
      ksort( $flipped );
    }
    return array_flip( $flipped );
  }

  private function decompileMatrix( $index )
  {
    foreach( $this->matrix['key_order'] as $i => $row )
    {
          $this->deciphertext .= $this->matrix['decipher_table'][$i][ $index ];
    }
/**
    foreach( $this->matrix[1] as $i => $row )
    {
          $this->deciphertext .= $this->matrix[1][$i][1];

    }
    foreach( $this->matrix[1] as $i => $row )
    {
          $this->deciphertext .= $this->matrix[1][$i][2];

    }
**/
    //return true;
  }

  private function readMatrix( $pretty )
  {
    $this->deciphertext = '';
    $pieces = $this->text['length'] / $this->key['length'];
    $order = $this->flipMatrix( true );
    asort( $order );
    for( $i = 0; $i < $pieces; $i++ ){
      $this->decompileMatrix( $i );
    }
    if( strlen( $this->deciphertext ) > 0 )
    {
      $this->deciphertext = ( $pretty == 1 ) ? ucwords( trim( $this->deciphertext ) ) : trim( $this->deciphertext );
      return true;
    }
    echo 'Error during decompilation';
    return false;
  }

  private function initializeEncryption( $fmt )
  {
    if( $this->calculateKeyOrder() )
    {
      if( $this->interpolateText() )
      {
        if( $this->createCipher( $fmt ) )
        {
          var_dump( $this->matrix );
          return $this->ciphertext;
        }
        return 'An error was encountered when attempting to create the ciphertext.'; 
      }
      return 'An error was encountered during the text interpolation process.'; 
    }
    return 'An error was encountered while calculating the key order.'; 
  }

  private function initializeDecryption( $fmt )
  {
    if( $this->calculateKeyOrder() )
    {
      if( $this->extrapolateText() )
      {
        if( $this->readMatrix( $fmt ) )
        {
          print_r( $this->matrix );
          return $this->deciphertext;
        }
        return 'An error was encountered when attempting to read the matrix.'; 
      }
      return 'An error was encountered during the text interpolation process.'; 
    }
    return 'An error was encountered while calculating the key order.'; 
  }

  public function encrypt( $params, $fmt = 0 )
  {
    if( $this->prepEncryption( $params['text'], $params['key'] ) )
    {
      return $this->initializeEncryption( $fmt );
    }
    return 'An error was encountered during the encryption preparation process.';
  }

  public function decrypt( $params, $fmt = 0 )
  {
    if( $this->prepDecryption( $params['text'], $params['key'] ) )
    {
      return $this->initializeDecryption( $fmt );
    }
    return 'An error was encountered during the decryption preparation process.';
  }

/**
  public static function getInstance()
  {
    if( static::$instance === NULL )
    {
      static::$instance = new self();
    }
    return static::$instance;
  }
  **/

}
