<?php 

namespace jwksConverter;
// biblioteca necessária para rodar funções relacionadas ao JWT, baixar via composer
require 'vendor/autoload.php';
use \Firebase\JWT\JWT;



class JwksConverter {

        // Classe para obter a chave pública dos certificados do IdP
        // Usados para verificar a validade dos tokens que a aplicação recebeu

    // recebe a url para obter o jwks
    // retorna um array associativo com os índices modulo e expoente (da chave)

    public function __construct($endereco_ip) {
        $this->endereco_ip = $endereco_ip;
    }

    public function pegaChave(){



    $url = "https://{$this->endereco_ip}/oauth2/jwks";

    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_URL => $url,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_RETURNTRANSFER => true,
    ));
    $response = curl_exec($curl);
    curl_close($curl);
    $response = json_decode($response,true);
    $modulo = $response['keys'][0]['n'];
    $expoente = $response['keys'][0]['e'];
    
    $mod_e_expoente = array(
        "modulo"=>$modulo,
        "expoente"=>$expoente
    );

    return $this->converteExpoenteEModuloEmPem($mod_e_expoente['modulo'],$mod_e_expoente['expoente']);
} 



    // recebe o módulo e o expoente da chave e retorna uma string com a chave 
    // público no formato pem
    public function converteExpoenteEModuloEmPem($n, $e)
    {
        $modulus = JWT::urlsafeB64Decode($n);
        $publicExponent = JWT::urlsafeB64Decode($e);
        $components = array(
            'modulus' => pack('Ca*a*', 2, self::encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', 2, self::encodeLength(strlen($publicExponent)), $publicExponent)
        );
        $RSAPublicKey = pack(
            'Ca*a*a*',
            48,
            self::encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );
        // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
        $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
        $RSAPublicKey = chr(0) . $RSAPublicKey;
        $RSAPublicKey = chr(3) . self::encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;
        $RSAPublicKey = pack(
            'Ca*a*',
            48,
            self::encodeLength(strlen($rsaOID . $RSAPublicKey)),
            $rsaOID . $RSAPublicKey
        );
        $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($RSAPublicKey), 64) .
            '-----END PUBLIC KEY-----';
        return $RSAPublicKey;
    }

    private static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }
        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
    

}