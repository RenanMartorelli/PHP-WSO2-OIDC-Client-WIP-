<?php 

namespace OauthSSO;

/* 
FLUXO DA CHAMADA DE AUTENTICAÇÃO VIA OAUTH2 AUTHORIZATION CODE 
GRANT TYPE 
IdP = Identity Provider (WSO2)
SP = Service Provider (Aplicação)

1. A aplicação redireciona o usuário para a url de SSO do 
IdP passando como parâmetros a URL de callback e o Client ID
gerado pelo IdP

2. O usuário se autentica no IdP usando suas credenciais de acesso,
se confirmado o login, o usuário é redirecionado para o SP com
um "authorization code"

3. A aplicação faz um chamado HTTP para o IdP usando o
authorization code, client_secret, client_id, callback_uri.

4. O IP retorna como resposta um JSON com:
Access Token -> usado para acessar API's como o SCIM
Refresh Token -> Um Grant Type WSO2 usado para evitar que seja gerado
um novo Token
ID Token -> Token JWT contendo os parâmetros (claims) do usuário para o
sistema

5. O sistema verifica se o token JWT está assinado corretamente
através da chave pública do IdP. Se estiver incorreto a autenticação
é invalidada. Se correto o login é realizado.
*/

// endpoint de autorização do WSO2
//$authorize_url = "https://{ip}:{porta}/oauth2/authorize";

//endpoint para pegar token de acesso
//$token_url = "https://{ip}:{porta}/oauth2/token";

//url para qual a aplicação será direcionada após a autenticação
//irá receber os parâmetros para pedir o token de acesso via GET
//$callback_uri = "http://{ip-aplicação}/app.php";

//Exemplo de credenciais do Service Provider Oauth criado no IdP
//DEVE SER MANTIDO EM SEGURANÇA
//$client_id = "WENsN2tofdgeEGWfUprNn_Vgpxga";
//$client_secret = "u7QW9fgrQxp8VW_SY_SEqgIH4fAa";


// Exemplo de chave pública para validar o JWT
// Deve ser pega e tratada através de outro código que realiza 
// um chamado para um endopoint específico do IdP.
//DEVE SER MANTIDO EM SEGURANÇA
// $public_key = <<<EOD
// -----BEGIN PUBLIC KEY----- 
// MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQCuB/dYzFw6JPzUi+ewW0I8
// LB9JVuUqx8WGr5hYHmfW6/jqMGwtZKodZXq3yBUnd9cdU7PCnBUSfIdDT4tCWh2m
// JrU47gjXuUahJtL4m0quuRPmVAEpj43lYVrKvoqIFzsEnnZJ8mWT4vujYtQpp+bx
// cN0vlyjA0tnf//wh5a14lrRe5W4eEOubAxk18cRgbH5tThfCx/RTHa73goEp6pNZ
// fprqLT02+ra8HBekhrPGpQLD0is0HbBXalCbzVunQAcEqBTG7tWFIU22TThEE3yz
// RWoJCTj+u/ZG+X8RgOgKSlgGYXFZa5bWbIB6R6hz81KJfoEA5hPCnU2Xv4zNvPo9
// AgMBAAE=
// -----END PUBLIC KEY-----
// EOD;


// biblioteca necessária para rodar funções relacionadas ao JWT, baixar via composer
require 'vendor/autoload.php';
use \Firebase\JWT\JWT;

class OauthSSO {
private $endereco_ip;
private $callback_uri;
private $client_id;
private $client_secret;
private $token_url;
private $authorize_url;
private $public_key;

	public function __construct($endereco_ip, $callback_uri, $client_id, $client_secret, $public_key) {
		$this->endereco_ip = $endereco_ip;
		$this->callback_uri = $callback_uri;
		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->public_key = $public_key;

		$this->token_url = "https://{$this->endereco_ip}/oauth2/token";
		$this->authorize_url = "https://{$this->endereco_ip}/oauth2/authorize";
	  }

	//Redirect para página de autenticação do IdP - passo 1.

	// recebe url da página de login do IdP, client ID do SP Oauth e url de callback
	
	public function pegaAuthorizationCode() {

		$authorization_redirect_url = $this->authorize_url . "?response_type=code&client_id=" . $this->client_id . "&redirect_uri=" . $this->callback_uri . "&scope=openid";
		header("Location: " . $authorization_redirect_url);
	}



	// requisição HTTP para pegar os tokens de acesso do IdP - passo 3,

	// recebe o authorization code obtido no passo 1, chave pública do IdP, url da
	// requisição, url de callback e as credenciais do SP Oauth
	// retorna array associativo com os índices accessToken(string), 
	// refreshToken(string) e idToken(json)

	public function pegaAccessToken($authorization_code, $public_key) {

		$authorization = base64_encode("{$this->client_id}:{$this->client_secret}");
		$header = array("Authorization: Basic {$authorization}","Content-Type: application/x-www-form-urlencoded");
		$content = "grant_type=authorization_code&code=$authorization_code&redirect_uri={$this->callback_uri}";

		$curl = curl_init();
		curl_setopt_array($curl, array(
			CURLOPT_URL => $this->token_url,
			CURLOPT_HTTPHEADER => $header,
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_POST => true,
			CURLOPT_POSTFIELDS => $content
		));
		$response = curl_exec($curl);
		curl_close($curl);
		
		echo $response;

		if ($response === false) {
			echo "Failed";
			echo curl_error($curl);
			echo "Failed";
		} elseif (isset(json_decode($response)->error)) {
			echo "Error:<br />";
			echo $authorization_code;
			echo $response;
		}

		$jwt = json_decode($response)->id_token;
		// Função para decodificar o token fazendo a validação
		$idToken = JWT::decode($jwt, $public_key, array('RS256'));
		// Caso haja falha na verificação, cancelar autenticação


		$accessToken = json_decode($response)->access_token;
		$refreshToken = json_decode($response)->refresh_token;

		$tokens = array(
			"accessToken"=>$accessToken, 
			"refreshToken"=>$refreshToken,
			"idToken"=>$idToken
		);

		return $tokens;

	}

	
}







